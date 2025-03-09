from abc import ABC, abstractmethod

class SecurityRule(ABC):
    def __init__(self, name: str, severity: str, pattern: str):
        self.name = name
        self.severity = severity
        self.pattern = pattern

    @abstractmethod
    def check(self, parse) -> list:
        """
        Run the security rule check against the parsed configuration.
        Returns a list of details if a vulnerability is found,
        or an empty list if no issues.
        """
        pass
