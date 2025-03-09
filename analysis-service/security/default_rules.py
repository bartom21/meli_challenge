from security.presence_based_security_rule import PresenceBasedSecurityRule
from security.absence_based_security_rule import AbsenceBasedSecurityRule

# Define default security rules (only the rules).
default_rules = [
    # Presence-based rules: trigger when the pattern is found.
    PresenceBasedSecurityRule("Weak password detected", "High", r"password 0|authentication plain-text-password"),
    PresenceBasedSecurityRule("Insecure SNMP community string", "High", r"snmp-server community (public|private)"),
    PresenceBasedSecurityRule("Overly permissive ACL", "High", r"access-list .* permit ip any any"),
    PresenceBasedSecurityRule("Insecure management access (Telnet enabled)", "Medium", r"(transport input telnet|set system services telnet)"),
    
    # Absence-based rule: trigger when the expected logging configuration is missing.
    AbsenceBasedSecurityRule("Logging configuration", "Medium", r"(logging (buffered|host)|set system syslog host)")
]
