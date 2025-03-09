from security.security_rule import SecurityRule

class SecurityAnalyzer:
    def __init__(self, rules=None):
        self.rules = rules if rules is not None else []

    def add_rule(self, rule: SecurityRule):
        self.rules.append(rule)

    def run(self, parse) -> list:
        findings = []
        for rule in self.rules:
            details = rule.check(parse)
            if details:
                findings.append({
                    "issue": rule.name,
                    "severity": rule.severity,
                    "details": details
                })
        return findings
