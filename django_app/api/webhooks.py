# ============================================================
# webhooks.py — Webhook Alerting for PromptGuard BLOCK Events
# ============================================================
# Fires an async webhook POST when a high-severity prompt is
# blocked (decision=BLOCK, risk_score >= threshold).
# ============================================================

import json
import logging
import threading
import urllib.error
import urllib.request
from datetime import datetime, timezone

from django.conf import settings

logger = logging.getLogger("promptguard.webhooks")


def send_block_webhook(
    *,
    decision: str,
    risk_score: int,
    attack_types: list,
    reasoning: list,
    client_ip: str,
    request_id: str,
    prompt_snippet: str = "",
    path: str = "",
):
    """
    Fire an asynchronous webhook when a prompt is blocked with a high risk
    score.

    The webhook is only sent when ALL of these conditions are true:
      - decision == "BLOCK"
      - risk_score >= PROMPTGUARD_WEBHOOK_THRESHOLD (default: 80)
      - PROMPTGUARD_WEBHOOK_URL is configured and non-empty

    The POST is dispatched in a daemon thread so it never blocks the
    API response. Delivery failures are logged but never raise.
    """
    webhook_url = getattr(settings, "PROMPTGUARD_WEBHOOK_URL", "")
    threshold = getattr(settings, "PROMPTGUARD_WEBHOOK_THRESHOLD", 80)

    if not webhook_url:
        return
    if decision != "BLOCK":
        return
    if risk_score < threshold:
        return

    payload = {
        "event": "prompt_blocked",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "request_id": request_id,
        "risk_score": risk_score,
        "attack_types": attack_types,
        "reasoning": reasoning[:3],  # First 3 reasons to keep payload small
        "client_ip": client_ip or "unknown",
        "path": path,
        "prompt_snippet": (prompt_snippet[:200] + "...") if len(prompt_snippet) > 200 else prompt_snippet,
        "severity": "CRITICAL" if risk_score >= 90 else "HIGH",
    }

    thread = threading.Thread(
        target=_deliver_webhook,
        args=(webhook_url, payload),
        daemon=True,
    )
    thread.start()


def _deliver_webhook(url: str, payload: dict):
    """Send the webhook POST. Retries once on failure. Never raises."""
    data = json.dumps(payload).encode("utf-8")

    for attempt in range(2):
        try:
            req = urllib.request.Request(
                url,
                data=data,
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=10) as response:
                logger.info(
                    "Webhook delivered to %s (status %s, request_id=%s)",
                    url,
                    response.status,
                    payload.get("request_id", "?"),
                )
                return

        except (urllib.error.URLError, urllib.error.HTTPError, OSError) as e:
            logger.warning(
                "Webhook delivery attempt %d failed for %s: %s",
                attempt + 1,
                url,
                e,
            )
            if attempt == 0:
                import time
                time.sleep(1)

        except Exception as e:
            logger.error("Unexpected webhook error: %s", e)
            return

    logger.error(
        "Webhook delivery failed after 2 attempts for request_id=%s",
        payload.get("request_id", "?"),
    )
