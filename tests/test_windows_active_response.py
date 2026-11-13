# Unit checks for windows/active-response/nixguard-remediate.py (IP block) and nixguard-unblock-ip.py, runnable on any
# OS: subprocess.run is replaced by a fake netsh that keeps rules in memory, and the log goes to a temp file.
# Run: python3 -m unittest discover -s tests -p "test_*.py"
import importlib.util
import io
import json
import os
import re
import sys
import tempfile
import unittest
from unittest import mock

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RESULT_LINE = re.compile(r"^\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2} active-response/bin/nixguard-(remediate|unblock-ip): (\{.*\})$")
RUN = "ngr-0123456789abcdef0123"


def load(name):
    spec = importlib.util.spec_from_file_location(name.replace("-", "_"), os.path.join(ROOT, "windows", "active-response", f"{name}.py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class FakeNetsh:
    def __init__(self, rules=(), add_works=True):
        self.rules = list(rules)
        self.calls = []
        self.add_works = add_works

    def __call__(self, args, **_):
        self.calls.append(args)
        assert args[:3] == ["netsh", "advfirewall", "firewall"], args
        name = next(a[5:] for a in args if a.startswith("name="))
        verb = args[3]
        code = 0
        if verb == "show":
            code = 0 if name in self.rules else 1
        elif verb == "add" and self.add_works:
            self.rules.append(name)
        elif verb == "delete":
            code = 0 if name in self.rules else 1
            self.rules = [r for r in self.rules if r != name]
        return mock.Mock(returncode=code, stdout=b"", stderr=b"")


class Base(unittest.TestCase):
    def run_script(self, name, extra_args, netsh):
        module = load(name)
        log = tempfile.NamedTemporaryFile(delete=False)
        log.close()
        self.addCleanup(os.unlink, log.name)
        module.LOG_FILE = log.name
        stdin = io.StringIO(json.dumps({"version": 1, "command": "add", "parameters": {"extra_args": extra_args}}) + "\n")
        with mock.patch.object(module.subprocess, "run", netsh), mock.patch.object(sys, "stdin", stdin):
            module.main()
        with open(log.name) as f:
            results = [json.loads(m.group(2)) for m in map(RESULT_LINE.match, f.read().splitlines()) if m]
        return results[-1] if results else None


class Block(Base):
    def test_block_reads_the_rule_back(self):
        netsh = FakeNetsh()
        r = self.run_script("nixguard-remediate", ["203.0.113.7", RUN], netsh)
        self.assertEqual(r["nixguard"], {"action": "block-ip", "target": "203.0.113.7", "run": RUN, "result": "success", "reason": "blocked"})
        self.assertEqual(r["command"], "add")
        self.assertEqual(netsh.rules, ["NixGuard Block 203.0.113.7"])

    def test_block_already_in_place(self):
        netsh = FakeNetsh(["NixGuard Block 203.0.113.7"])
        r = self.run_script("nixguard-remediate", ["203.0.113.7", RUN], netsh)
        self.assertEqual(r["nixguard"]["reason"], "already-blocked")
        self.assertEqual(netsh.rules, ["NixGuard Block 203.0.113.7"])

    def test_block_failure_is_reported(self):
        r = self.run_script("nixguard-remediate", ["203.0.113.7", RUN], FakeNetsh(add_works=False))
        self.assertEqual((r["nixguard"]["result"], r["nixguard"]["reason"]), ("failure", "netsh-failed"))

    def test_bad_run_id_is_dropped(self):
        for bad in ["ngr-XYZ", "ngr-0123456789abcdef\"}", "$(id)", 5]:
            r = self.run_script("nixguard-remediate", ["203.0.113.7", bad], FakeNetsh())
            self.assertEqual(r["nixguard"]["run"], "")


class Unblock(Base):
    def test_unblock_removes_the_named_rule(self):
        netsh = FakeNetsh(["NixGuard Block 203.0.113.7", "NixGuard Block 203.0.113.70", "Other rule"])
        r = self.run_script("nixguard-unblock-ip", ["203.0.113.7", RUN], netsh)
        self.assertEqual(r["nixguard"], {"action": "unblock-ip", "target": "203.0.113.7", "run": RUN, "result": "success", "reason": "unblocked"})
        self.assertEqual(r["command"], "delete")
        self.assertEqual(netsh.rules, ["NixGuard Block 203.0.113.70", "Other rule"])

    def test_unblock_when_not_blocked(self):
        r = self.run_script("nixguard-unblock-ip", ["203.0.113.7", RUN], FakeNetsh())
        self.assertEqual(r["nixguard"]["reason"], "not-blocked")

    def test_unblock_refuses_anything_but_ipv4(self):
        for bad in ["203.0.113.7 dir=out", "203.0.113.7\" name=x", "any", "203.0.113.256", "", "2001:db8::1", ["203.0.113.7"], None]:
            netsh = FakeNetsh(["NixGuard Block 203.0.113.7"])
            r = self.run_script("nixguard-unblock-ip", [bad, RUN], netsh)
            self.assertEqual((r["nixguard"]["result"], r["nixguard"]["reason"], r["nixguard"]["target"]), ("failure", "invalid-target", ""), bad)
            self.assertEqual(netsh.calls, [], bad)


if __name__ == "__main__":
    unittest.main()
