# ============================================================
# decision.py — Decision Engine
# ============================================================
# Translates a numeric risk score into a human-readable
# decision: ALLOW, WARN, or BLOCK.
#
# Thresholds (from project spec):
#   0  – 29  → ALLOW  (safe, no threats detected)
#   30 – 69  → WARN   (suspicious, flagged for review)
#   70 – 100 → BLOCK  (malicious, rejected)
# ============================================================


def make_decision(risk_score: int) -> tuple:
    """
    Convert a risk score into a (decision, threat_level) tuple.

    Args:
        risk_score: Integer 0–100

    Returns:
        Tuple of (decision: str, threat_level: str)
        e.g. ('BLOCK', 'HIGH') or ('ALLOW', 'LOW')
    """
    if risk_score >= 70:
        return "BLOCK", "HIGH"
    elif risk_score >= 30:
        return "WARN", "MEDIUM"
    else:
        return "ALLOW", "LOW"