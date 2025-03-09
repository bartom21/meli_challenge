from security.security_rule import SecurityRule

class PresenceBasedSecurityRule(SecurityRule):
    """
    A rule that triggers a vulnerability when the given pattern is present.
    """
    def check(self, parse) -> list:
        matches = parse.find_objects(self.pattern)
        return [entry.text for entry in matches] if matches else []
