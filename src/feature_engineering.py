from typing import Any


HIGH_RISK_TERMS = {
    "ransomware",
    "remote code execution",
    "zero-day",
    "actively exploited",
    "data exfiltration",
    "credential theft",
    "lateral movement",
    "privilege escalation",
    "command and control",
    "critical infrastructure",
    "malicious payload",
    "persistence",
}


def create_features(
    text: str,
    entities: dict[str, Any],
) -> dict[str, float]:
    """
    Convert extracted threat-report entities into numerical features.
    """
    if not isinstance(text, str):
        raise TypeError("text must be a string")

    if not isinstance(entities, dict):
        raise TypeError("entities must be a dictionary")

    categorized = entities.get("categorized_entities", {})
    text_lower = text.lower()

    matched_high_risk_terms = [
        term
        for term in HIGH_RISK_TERMS
        if term in text_lower
    ]

    cve_count = len(entities.get("cves", []))
    attack_id_count = len(entities.get("attack_ids", []))
    ip_count = len(entities.get("ip_addresses", []))
    url_count = len(entities.get("urls", []))
    hash_count = len(entities.get("hashes", []))

    threat_actor_count = len(
        categorized.get("threat_actors", [])
    )
    malware_count = len(
        categorized.get("malware", [])
    )
    tool_count = len(
        categorized.get("tools", [])
    )
    technique_count = len(
        categorized.get("techniques", [])
    )
    campaign_count = len(
        categorized.get("campaigns", [])
    )

    indicator_count = (
        ip_count
        + url_count
        + hash_count
    )

    return {
        "cve_count": float(cve_count),
        "attack_id_count": float(attack_id_count),
        "ip_count": float(ip_count),
        "url_count": float(url_count),
        "hash_count": float(hash_count),
        "indicator_count": float(indicator_count),
        "threat_actor_count": float(threat_actor_count),
        "malware_count": float(malware_count),
        "tool_count": float(tool_count),
        "technique_count": float(technique_count),
        "campaign_count": float(campaign_count),
        "high_risk_term_count": float(
            len(matched_high_risk_terms)
        ),
        "text_length": float(len(text)),
        "word_count": float(len(text.split())),
    }


def get_matched_risk_terms(
    text: str,
) -> list[str]:
    """
    Return the high-risk terms detected in the report text.
    """
    if not isinstance(text, str):
        raise TypeError("text must be a string")

    text_lower = text.lower()

    return sorted(
        term
        for term in HIGH_RISK_TERMS
        if term in text_lower
    )