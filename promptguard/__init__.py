# ============================================================
# __init__.py — The promptguard Python Library
# ============================================================
# This is what developers import. The entire library is
# accessed through one class: Firewall.
#
# Usage:
#   from promptguard import Firewall
#   fw = Firewall(api_key="YOUR_GEMINI_KEY")
#   result = fw.analyze("Ignore previous instructions")
#   print(result.decision)    # 'BLOCK'
#   print(result.risk_score)  # 85
# ============================================================

import time
from dataclasses import dataclass, field
from typing import Optional

from .analyzer import generative_analyze, generative_analyze_image, generative_analyze_output


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
    reasons: list             # plain-English explanation list from the AI
    ai_reasoning: str         # full AI reasoning as a single string
    processing_time_ms: float  # how long the analysis took
    analysis_available: bool = True  # True when Gemini produced the verdict
    fallback_used: bool = False       # True when local fallback was used

    def is_safe(self) -> bool:
        """Returns True only if the decision is ALLOW."""
        return self.decision == "ALLOW"

    def __str__(self) -> str:
        lines = [
            f"Decision:      {self.decision}",
            f"Threat Level:  {self.threat_level}",
            f"Risk Score:    {self.risk_score} / 100",
            f"Attack Types:  {', '.join(self.attack_types) if self.attack_types else 'None'}",
            f"AI Reasoning:",
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

    Uses the Gemini LLM to analyze prompts for injection attacks
    and returns a structured FirewallResult object.

    Example:
        fw = Firewall(api_key="YOUR_GEMINI_KEY")
        result = fw.analyze("Ignore all previous instructions")
        if not result.is_safe():
            print("Attack blocked:", result.reasons)
    """

    def __init__(self, api_key: str = None, model: str = "gemini-2.5-flash"):
        """
        Args:
            api_key: Gemini API key. If not provided, falls back to
                     GEMINI_API_KEY or GOOGLE_API_KEY environment variables.
            model:   Gemini model to use (default: gemini-2.5-flash).
        """
        self.api_key = api_key
        self.model = model

    def analyze(self, prompt: str, session_context: list = None) -> FirewallResult:
        """
        Analyse a prompt using generative AI detection.

        Args:
            prompt:          The user's input string to evaluate.
            session_context: Optional list of recent prompt strings from the
                             same session for multi-turn attack detection.

        Returns:
            FirewallResult object with full analysis details.
        """
        start_time = time.time()

        # --- Generative AI Analysis ---
        result = generative_analyze(
            prompt=prompt,
            api_key=self.api_key,
            model=self.model,
            session_context=session_context,
        )

        elapsed_ms = (time.time() - start_time) * 1000

        # Build the ai_reasoning string from the list
        reasoning_list = result.get("reasoning", [])
        ai_reasoning_str = " | ".join(reasoning_list) if reasoning_list else "No analysis available"

        return FirewallResult(
            decision=result["decision"],
            threat_level=result["threat_level"],
            risk_score=result["risk_score"],
            attack_types=result["attack_types"],
            reasons=reasoning_list,
            ai_reasoning=ai_reasoning_str,
            processing_time_ms=elapsed_ms,
            analysis_available=bool(result.get("analysis_available", True)),
            fallback_used=bool(result.get("fallback_used", False)),
        )

    def analyze_image(self, image_base64: str, mime_type: str) -> FirewallResult:
        """
        Analyse an image using Gemini's multimodal vision capability.

        Args:
            image_base64: Base64-encoded image bytes.
            mime_type:     MIME type (e.g. "image/png").

        Returns:
            FirewallResult object with full analysis details.
        """
        start_time = time.time()

        result = generative_analyze_image(
            image_base64=image_base64,
            mime_type=mime_type,
            api_key=self.api_key,
            model=self.model,
        )

        elapsed_ms = (time.time() - start_time) * 1000

        reasoning_list = result.get("reasoning", [])
        ai_reasoning_str = " | ".join(reasoning_list) if reasoning_list else "No analysis available"

        return FirewallResult(
            decision=result["decision"],
            threat_level=result["threat_level"],
            risk_score=result["risk_score"],
            attack_types=result["attack_types"],
            reasons=reasoning_list,
            ai_reasoning=ai_reasoning_str,
            processing_time_ms=elapsed_ms,
            analysis_available=bool(result.get("analysis_available", True)),
            fallback_used=bool(result.get("fallback_used", False)),
        )

    def scan_output(self, llm_response: str) -> FirewallResult:
        """
        Scan an LLM response for unsafe content before returning it to the user.

        Detects prompt leakage, jailbreak compliance, hallucinated PII,
        echoed injections, and other unsafe output content.

        Args:
            llm_response: The raw LLM response text to scan.

        Returns:
            FirewallResult object with output scan details.
        """
        start_time = time.time()

        result = generative_analyze_output(
            llm_response=llm_response,
            api_key=self.api_key,
            model=self.model,
        )

        elapsed_ms = (time.time() - start_time) * 1000

        reasoning_list = result.get("reasoning", [])
        ai_reasoning_str = " | ".join(reasoning_list) if reasoning_list else "No analysis available"

        return FirewallResult(
            decision=result["decision"],
            threat_level=result["threat_level"],
            risk_score=result["risk_score"],
            attack_types=result["attack_types"],
            reasons=reasoning_list,
            ai_reasoning=ai_reasoning_str,
            processing_time_ms=elapsed_ms,
            analysis_available=bool(result.get("analysis_available", True)),
            fallback_used=bool(result.get("fallback_used", False)),
        )

