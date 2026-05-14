# ============================================================
# __init__.py — The promptguard Python Library
# ============================================================
# This is what developers import. The entire library is
# accessed through one class: Firewall.
#
# Usage:
#   from promptguard import Firewall
#   fw = Firewall()
#   result = fw.analyze("Ignore previous instructions")
#   print(result.decision)    # 'BLOCK'
#   print(result.risk_score)  # 91
# ============================================================

import time
from dataclasses import dataclass, field
from typing import Optional

from .patterns import scan_patterns
from .semantic import get_semantic_score
from .scorer import calculate_risk_score, generate_reasons
from .decision import make_decision


@dataclass
class FirewallResult:
    """
    The structured result object returned by Firewall.analyze().

    Every field is always populated — no None surprises for the caller.
    """
    decision: str             # 'ALLOW', 'WARN', or 'BLOCK'
    threat_level: str         # 'LOW', 'MEDIUM', or 'HIGH'
    risk_score: int           # 0–100
    attack_types: list        # e.g. ['instruction_override', 'data_exfiltration']
    reasons: list             # plain-English explanation list
    pattern_hits: dict        # raw Layer 1 output (attack_type -> matched phrases)
    semantic_score: float     # raw Layer 2 output (0.0–1.0)
    semantic_attack_type: Optional[str]  # which category had highest semantic match
    processing_time_ms: float  # how long the analysis took

    def is_safe(self) -> bool:
        """Returns True only if the decision is ALLOW."""
        return self.decision == "ALLOW"

    def __str__(self) -> str:
        lines = [
            f"Decision:      {self.decision}",
            f"Threat Level:  {self.threat_level}",
            f"Risk Score:    {self.risk_score} / 100",
            f"Attack Types:  {', '.join(self.attack_types) if self.attack_types else 'None'}",
            f"Reasons:",
        ]
        if self.reasons:
            for r in self.reasons:
                lines.append(f"  - {r}")
        else:
            lines.append("  - No threats detected")
        lines.append(f"Time:          {self.processing_time_ms:.1f}ms")
        return "\n".join(lines)


class Firewall:
    """
    The main entry point for the promptguard library.

    Runs all three detection layers on a prompt and returns
    a structured FirewallResult object.

    Example:
        fw = Firewall()
        result = fw.analyze("Ignore all previous instructions")
        if not result.is_safe():
            print("Attack blocked:", result.reasons)
    """

    def __init__(self, use_semantic: bool = True):
        """
        Args:
            use_semantic: If True (default), runs Layer 2 semantic analysis.
                          Set to False for faster but less thorough detection
                          (Layer 1 pattern matching only).
        """
        self.use_semantic = use_semantic

    def analyze(self, prompt: str) -> FirewallResult:
        """
        Analyse a prompt through all detection layers.

        Args:
            prompt: The user's input string to evaluate.

        Returns:
            FirewallResult object with full analysis details.
        """
        start_time = time.time()

        # --- Layer 1: Pattern Detection ---
        pattern_hits = scan_patterns(prompt)

        # --- Layer 2: Semantic Analysis ---
        semantic_score = 0.0
        semantic_attack_type = None

        if self.use_semantic:
            semantic_score, semantic_attack_type = get_semantic_score(prompt)

        # --- Layer 3: Risk Scoring ---
        risk_score = calculate_risk_score(pattern_hits, semantic_score)
        reasons = generate_reasons(pattern_hits, semantic_score)

        # --- Decision ---
        decision, threat_level = make_decision(risk_score)

        # Collect all detected attack types
        attack_types = list(pattern_hits.keys())
        if (
            semantic_attack_type
            and semantic_score >= 0.60
            and semantic_attack_type not in attack_types
        ):
            attack_types.append(semantic_attack_type)

        elapsed_ms = (time.time() - start_time) * 1000

        return FirewallResult(
            decision=decision,
            threat_level=threat_level,
            risk_score=risk_score,
            attack_types=attack_types,
            reasons=reasons,
            pattern_hits=pattern_hits,
            semantic_score=semantic_score,
            semantic_attack_type=semantic_attack_type,
            processing_time_ms=elapsed_ms,
        )