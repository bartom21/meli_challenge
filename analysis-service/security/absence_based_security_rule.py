from security.security_rule import SecurityRule

class AbsenceBasedSecurityRule(SecurityRule):
    """
    A rule that triggers a vulnerability when the given pattern is absent.
    
    """
    def check(self, parse) -> list:
        if not parse.find_objects(self.pattern):
            return [f"{self.name} not found"]
        return []
