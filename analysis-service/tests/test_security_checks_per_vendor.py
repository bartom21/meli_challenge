from security.security_analyzer import SecurityAnalyzer
from security.default_rules import default_rules
from ciscoconfparse2 import CiscoConfParse

def run_default_security_checks(parse):
    """Helper to instantiate the SecurityAnalyzer with default_rules and return the findings."""
    analyzer = SecurityAnalyzer(default_rules)
    return analyzer.run(parse)

def get_finding_by_issue(findings, issue):
    """Helper to return the first finding matching the given issue name."""
    for f in findings:
        if f["issue"] == issue:
            return f
    return None

# === Weak Passwords Tests ===

# Cisco
def test_weak_passwords_cisco_positive():
    config = (
        "username admin privilege 15 password 0 weakpass123\n"
        "logging buffered 64000"
    )
    findings = run_default_security_checks(CiscoConfParse(config.splitlines()))
    expected = {
        "issue": "Weak password detected",
        "severity": "High",
        "details": ["username admin privilege 15 password 0 weakpass123"]
    }
    finding = get_finding_by_issue(findings, "Weak password detected")
    assert finding == expected

def test_weak_passwords_cisco_negative():
    config = (
        "username admin privilege 15 secret strongpassword\n"
        "logging buffered 64000"
    )
    findings = run_default_security_checks(CiscoConfParse(config.splitlines()))
    finding = get_finding_by_issue(findings, "Weak password detected")
    assert finding is None

# Juniper
def test_weak_passwords_juniper_positive():
    config = (
        "set system login user admin authentication plain-text-password weakpass123\n"
        "logging buffered 64000"
    )
    findings = run_default_security_checks(CiscoConfParse(config.splitlines()))
    expected = {
        "issue": "Weak password detected",
        "severity": "High",
        "details": ["set system login user admin authentication plain-text-password weakpass123"]
    }
    finding = get_finding_by_issue(findings, "Weak password detected")
    assert finding == expected

def test_weak_passwords_juniper_negative():
    config = (
        "set system login user admin authentication encrypted strongpassword\n"
        "logging buffered 64000"
    )
    findings = run_default_security_checks(CiscoConfParse(config.splitlines()))
    finding = get_finding_by_issue(findings, "Weak password detected")
    assert finding is None

# === Insecure SNMP Tests ===

# Cisco
def test_insecure_snmp_cisco_positive():
    config = (
        "snmp-server community public RO\n"
        "logging buffered 64000"
    )
    findings = run_default_security_checks(CiscoConfParse(config.splitlines()))
    expected = {
        "issue": "Insecure SNMP community string",
        "severity": "High",
        "details": ["snmp-server community public RO"]
    }
    finding = get_finding_by_issue(findings, "Insecure SNMP community string")
    assert finding == expected

def test_insecure_snmp_cisco_negative():
    config = (
        "snmp-server community securecommunity RO\n"
        "logging buffered 64000"
    )
    findings = run_default_security_checks(CiscoConfParse(config.splitlines()))
    finding = get_finding_by_issue(findings, "Insecure SNMP community string")
    assert finding is None

# Juniper
def test_insecure_snmp_juniper_positive():
    config = (
        "set snmp-server community public RO\n"
        "logging buffered 64000"
    )
    findings = run_default_security_checks(CiscoConfParse(config.splitlines()))
    expected = {
        "issue": "Insecure SNMP community string",
        "severity": "High",
        "details": ["set snmp-server community public RO"]
    }
    finding = get_finding_by_issue(findings, "Insecure SNMP community string")
    assert finding == expected

def test_insecure_snmp_juniper_negative():
    config = (
        "set snmp-server community securecommunity RO\n"
        "logging buffered 64000"
    )
    findings = run_default_security_checks(CiscoConfParse(config.splitlines()))
    finding = get_finding_by_issue(findings, "Insecure SNMP community string")
    assert finding is None

# === Overly Permissive ACL Tests ===

# Cisco
def test_open_acls_cisco_positive():
    config = (
        "access-list 100 permit ip any any\n"
        "logging buffered 64000"
    )
    findings = run_default_security_checks(CiscoConfParse(config.splitlines()))
    expected = {
        "issue": "Overly permissive ACL",
        "severity": "High",
        "details": ["access-list 100 permit ip any any"]
    }
    finding = get_finding_by_issue(findings, "Overly permissive ACL")
    assert finding == expected

def test_open_acls_cisco_negative():
    config = (
        "access-list 100 permit ip 192.168.1.0 0.0.0.255\n"
        "logging buffered 64000"
    )
    findings = run_default_security_checks(CiscoConfParse(config.splitlines()))
    finding = get_finding_by_issue(findings, "Overly permissive ACL")
    assert finding is None

# Juniper (simulate similar syntax)
def test_open_acls_juniper_positive():
    config = (
        "access-list 100 permit ip any any\n"
        "logging buffered 64000"
    )
    findings = run_default_security_checks(CiscoConfParse(config.splitlines()))
    expected = {
        "issue": "Overly permissive ACL",
        "severity": "High",
        "details": ["access-list 100 permit ip any any"]
    }
    finding = get_finding_by_issue(findings, "Overly permissive ACL")
    assert finding == expected

def test_open_acls_juniper_negative():
    config = (
        "access-list 100 permit ip 10.0.0.0 0.0.0.255\n"
        "logging buffered 64000"
    )
    findings = run_default_security_checks(CiscoConfParse(config.splitlines()))
    finding = get_finding_by_issue(findings, "Overly permissive ACL")
    assert finding is None

# === Insecure Management Access Tests ===

# Cisco
def test_insecure_mgmt_cisco_positive():
    config = (
        "transport input telnet\n"
        "logging buffered 64000"
    )
    findings = run_default_security_checks(CiscoConfParse(config.splitlines()))
    expected = {
        "issue": "Insecure management access (Telnet enabled)",
        "severity": "Medium",
        "details": ["transport input telnet"]
    }
    finding = get_finding_by_issue(findings, "Insecure management access (Telnet enabled)")
    assert finding == expected

def test_insecure_mgmt_cisco_negative():
    config = (
        "transport input ssh\n"
        "logging buffered 64000"
    )
    findings = run_default_security_checks(CiscoConfParse(config.splitlines()))
    finding = get_finding_by_issue(findings, "Insecure management access (Telnet enabled)")
    assert finding is None

# Juniper
def test_insecure_mgmt_juniper_positive():
    config = (
        "set system services telnet\n"
        "logging buffered 64000"
    )
    findings = run_default_security_checks(CiscoConfParse(config.splitlines()))
    expected = {
        "issue": "Insecure management access (Telnet enabled)",
        "severity": "Medium",
        "details": ["set system services telnet"]
    }
    finding = get_finding_by_issue(findings, "Insecure management access (Telnet enabled)")
    assert finding == expected

def test_insecure_mgmt_juniper_negative():
    config = (
        "set system services ssh\n"
        "logging buffered 64000"
    )
    findings = run_default_security_checks(CiscoConfParse(config.splitlines()))
    finding = get_finding_by_issue(findings, "Insecure management access (Telnet enabled)")
    assert finding is None

# === Logging Configuration Tests ===

# Cisco
def test_logging_disabled_cisco_positive():
    # No logging commands provided triggers logging not configured
    config = "username admin privilege 15 secret strongpassword"
    findings = run_default_security_checks(CiscoConfParse(config.splitlines()))
    expected = {
        "issue": "Logging configuration",
        "severity": "Medium",
        "details": ["Logging configuration not found"]
    }
    finding = get_finding_by_issue(findings, "Logging configuration")
    assert finding == expected

def test_logging_disabled_cisco_negative():
    config = "logging buffered 64000\nlogging host 192.168.1.100"
    findings = run_default_security_checks(CiscoConfParse(config.splitlines()))
    finding = get_finding_by_issue(findings, "Logging configuration")
    assert finding is None

# Juniper
def test_logging_disabled_juniper_positive():
    # No logging configuration provided in Juniper style
    config = "set system login user admin"
    findings = run_default_security_checks(CiscoConfParse(config.splitlines()))
    expected = {
        "issue": "Logging configuration",
        "severity": "Medium",
        "details": ["Logging configuration not found"]
    }
    finding = get_finding_by_issue(findings, "Logging configuration")
    assert finding == expected

def test_logging_disabled_juniper_negative():
    config = "set system syslog host 192.168.1.100"
    findings = run_default_security_checks(CiscoConfParse(config.splitlines()))
    finding = get_finding_by_issue(findings, "Logging configuration")
    assert finding is None
