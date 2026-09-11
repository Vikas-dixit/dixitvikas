from typing import Dict, Any, List

SENSITIVE_PORTS = {21: "FTP", 22: "SSH", 23: "Telnet", 3389: "RDP", 445: "SMB"}
SUSPICIOUS_PROCESSES = {"mimikatz", "nc", "netcat", "ncat", "powershell.exe"}


def analyze_event(event: Dict[str, Any]) -> Dict[str, Any]:
    score = 0
    reasons: List[str] = []

    if event.get("event_type") == "login" and event.get("success") is False:
        attempts = int(event.get("failed_attempts") or 0)
        if attempts >= 8:
            score += 60
            reasons.append("Repeated failed logins may indicate brute-force activity")
        elif attempts >= 4:
            score += 35
            reasons.append("Multiple failed login attempts detected")
        else:
            score += 10
            reasons.append("Failed login detected")

    port = event.get("destination_port")
    if port in SENSITIVE_PORTS:
        score += 20
        reasons.append(f"{SENSITIVE_PORTS[port]} is a sensitive remote/network service")

    process = (event.get("process_name") or "").lower()
    if process in SUSPICIOUS_PROCESSES:
        score += 30
        reasons.append(f"Process '{process}' can be abused during post-exploitation")

    if int(event.get("bytes_sent") or 0) > 50_000_000:
        score += 25
        reasons.append("Unusually large outbound data transfer detected")

    score = min(score, 100)

    if score >= 75:
        severity = "high"
    elif score >= 40:
        severity = "medium"
    elif score > 0:
        severity = "low"
    else:
        severity = "informational"
        reasons.append("No current detection rule considered this event suspicious")

    return {
        "severity": severity,
        "risk_score": score,
        "reasons": reasons,
        "recommendation": recommendation_for(severity),
    }


def recommendation_for(severity: str) -> str:
    recommendations = {
        "high": "Investigate immediately, validate the source, and contain the affected account or host if malicious activity is confirmed.",
        "medium": "Review surrounding logs and correlate this event with authentication, process, and network activity.",
        "low": "Keep the event for correlation and continue monitoring for repeated activity.",
        "informational": "No immediate action required.",
    }
    return recommendations[severity]
