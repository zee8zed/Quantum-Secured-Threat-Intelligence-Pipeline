from typing import Any


def classify_severity(
    features: dict[str, float],
    text: str,
) -> dict[str, Any]:
    """
    Classify report severity using an explainable rule-based baseline.

    This is not a trained machine-learning model.
    """

    if not isinstance(features, dict):
        raise TypeError("features must be a dictionary")

    if not isinstance(text, str):
        raise TypeError("text must be a string")

    score = 0
    reasons: list[str] = []

    cve_count = features.get("cve_count", 0.0)
    threat_actor_count = features.get("threat_actor_count", 0.0)
    malware_count = features.get("malware_count", 0.0)
    technique_count = features.get("technique_count", 0.0)
    indicator_count = features.get("indicator_count", 0.0)
    high_risk_term_count = features.get("high_risk_term_count", 0.0)

    if cve_count > 0:
        score += 2
        reasons.append(
            f"{int(cve_count)} CVE identifier(s) detected"
        )

    if threat_actor_count > 0:
        score += 2
        reasons.append(
            f"{int(threat_actor_count)} known threat actor(s) detected"
        )

    if malware_count > 0:
        score += 2
        reasons.append(
            f"{int(malware_count)} known malware entity/entities detected"
        )

    if technique_count > 0:
        score += 1
        reasons.append(
            f"{int(technique_count)} MITRE ATT&CK technique(s) detected"
        )

    if indicator_count >= 3:
        score += 2
        reasons.append(
            f"{int(indicator_count)} technical indicators detected"
        )
    elif indicator_count > 0:
        score += 1
        reasons.append(
            f"{int(indicator_count)} technical indicator(s) detected"
        )

    if high_risk_term_count >= 3:
        score += 4
        reasons.append(
            f"{int(high_risk_term_count)} high-risk terms detected"
        )
    elif high_risk_term_count > 0:
        score += 2
        reasons.append(
            f"{int(high_risk_term_count)} high-risk term(s) detected"
        )

    if score >= 9:
        severity = "Critical"
    elif score >= 6:
        severity = "High"
    elif score >= 3:
        severity = "Medium"
    else:
        severity = "Low"

    return {
        "severity": severity,
        "score": score,
        "reasons": reasons or [
            "No significant threat indicators detected"
        ],
        "method": "rule-based severity baseline",
    }