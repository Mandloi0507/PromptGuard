# ============================================================
# scorer.py - Layer 3: Risk Score Calculation
# ============================================================
# Takes pattern hits and semantic score and combines them into
# a single 0-100 risk score with human-readable reasons.
# ============================================================


def calculate_risk_score(pattern_hits: dict, semantic_score: float) -> int:
    """
    Calculate a risk score from 0-100 based on detection signals.

    Scoring breakdown:
        instruction_override pattern matched  -> +70 points
        data_exfiltration pattern matched     -> +70 points
        role_manipulation pattern matched     -> +45 points
        indirect_injection pattern matched    -> +65 points
        semantic score >= 0.80                -> +70 points
        semantic score >= 0.60                -> +35 points
        semantic score >= 0.35                -> +15 points
        more than one attack type detected    -> +10 bonus points
    """
    score = 0

    attack_weights = {
        "instruction_override": 70,
        "data_exfiltration": 70,
        "role_manipulation": 45,
        "indirect_injection": 65,
    }

    for attack_type, weight in attack_weights.items():
        if attack_type in pattern_hits:
            score += weight

    if semantic_score >= 0.80:
        score += 70
    elif semantic_score >= 0.60:
        score += 35
    elif semantic_score >= 0.35:
        score += 15

    if len(pattern_hits) > 1:
        score += 10

    return min(score, 100)


def generate_reasons(pattern_hits: dict, semantic_score: float) -> list:
    """Build a plain-English list of reasons explaining a decision."""
    reasons = []

    label_map = {
        "instruction_override": "Instruction override",
        "data_exfiltration": "Data exfiltration attempt",
        "role_manipulation": "Role/identity manipulation",
        "indirect_injection": "Indirect injection pattern",
    }

    for attack_type, matched_phrases in pattern_hits.items():
        label = label_map.get(attack_type, attack_type)
        example = matched_phrases[0]
        reasons.append(f"{label} pattern detected: '{example}'")

    if semantic_score >= 0.80:
        reasons.append(
            f"Very high semantic similarity to known attack patterns "
            f"(score: {semantic_score:.2f}) - block-level rephrased attack likely"
        )
    elif semantic_score >= 0.60:
        reasons.append(
            f"High semantic similarity to known attack patterns "
            f"(score: {semantic_score:.2f}) - rephrased attack likely"
        )
    if len(pattern_hits) > 1:
        types = " + ".join(label_map.get(t, t) for t in pattern_hits.keys())
        reasons.append(
            f"Multi-type attack combination detected: {types} - bonus risk applied"
        )

    return reasons
