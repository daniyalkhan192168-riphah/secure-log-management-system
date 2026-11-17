"""
One severity rule for the whole system (dashboard cards, chart, table colours
and filters all use this, so they can never disagree).
"""
LEVELS = ("critical", "high", "medium", "low")

_CRITICAL = ("INTEGRITY_ALERT", "TAMPER", "DEMO_ATTACK")
_HIGH = ("FAILED", "FAILURE", "ERROR", "DENIED", "INVALID", "BLOCKED")
_MEDIUM = ("SUCCESS", "SUDO", "ADMIN", "ACCESS", "SSH", "FIREWALL", "LOGIN", "AUTH",
           "ACCOUNT", "PRIVILEGE")
# Exact event types whose severity should not be guessed from keywords.
_EXACT = {
    "ROLLBACK_DETECTED": "critical",
    "SEAL_MISMATCH": "critical",
    "AGENT_SILENT": "high",
    "AGENT_STOPPED": "high",
    "AGENT_ONLINE": "low",
    "BRUTE_FORCE_DETECTED": "high",
    "BRUTE_FORCE_SUCCESS": "critical",
    "SUDO_PASSWORD_GUESSING": "high",
    "ADMIN_RIGHTS_GRANTED": "critical",
    "LOG_WIPING_DETECTED": "critical",
    "PORT_SCAN_DETECTED": "high",
}


def severity(event_type: str) -> str:
    event = (event_type or "").upper()
    if event in _EXACT:
        return _EXACT[event]
    if any(word in event for word in _CRITICAL):
        return "critical"
    if any(word in event for word in _HIGH):
        return "high"
    if any(word in event for word in _MEDIUM):
        return "medium"
    return "low"
