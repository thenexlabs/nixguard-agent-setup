"""Checks for manager/nixguard_ar_rules.xml: every NixGuard result rule is a child of the stock rule 657 and is at
level 5 or more, so the manager stores it at Wazuh's default log_alert_level (3) and at the common hardened one (4,
which NixGuard-provisioned managers use). Failures stay above successes.
Run: python3 tests/manager-rules.test.py
"""
import os
import sys
import xml.etree.ElementTree as ET

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
# A Wazuh rules file has no single root element; wrap it to parse it.
with open(os.path.join(ROOT, "manager", "nixguard_ar_rules.xml"), encoding="utf-8") as f:
    tree = ET.fromstring("<root>" + f.read() + "</root>")

failures = []
rules = {r.get("id"): r for r in tree.iter("rule")}
if sorted(rules) != ["100910", "100911", "100912", "100913"]:
    failures.append(f"unexpected rule ids {sorted(rules)}")
for rule_id, rule in rules.items():
    level = int(rule.get("level"))
    if rule.findtext("if_sid") != "657":
        failures.append(f"{rule_id}: not a child of 657")
    if level < 5:
        failures.append(f"{rule_id}: level {level} is under 5: a manager with log_alert_level 4 drops it")
    fields = {f.get("name"): f.text for f in rule.findall("field")}
    if fields.get("nixguard.result") == "^failure$" and level < 7:
        failures.append(f"{rule_id}: a failure should be level 7 or more")
for group in tree.iter("group"):
    if "active_response" not in group.get("name", "").split(","):
        failures.append("the rules must stay in the active_response group (kept out of act on new alerts)")

for line in failures:
    print("FAIL:", line)
print(f"{len(rules)} rules checked, {len(failures)} failures")
sys.exit(1 if failures else 0)
