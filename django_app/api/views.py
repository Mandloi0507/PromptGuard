import json
import sys
import os
import hashlib
import uuid

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))

from django.http import JsonResponse
from django.views.decorators.http import require_http_methods
from django.conf import settings

from promptguard import Firewall
from promptguard.adapters import get_adapter
from .models import PromptLog

firewall = Firewall(api_key=getattr(settings, 'GEMINI_API_KEY', None))
MAX_PROMPT_CHARS = 8000
MAX_LOG_CHARS = 1000
ALLOWED_LLMS = {"ollama", "claude", "anthropic", "openai", "gpt", "gemini", "google"}


def _error_response(message: str, status: int = 400, detail: Exception = None):
    payload = {"error": message}
    if detail is not None and settings.DEBUG:
        payload["detail"] = str(detail)
    return JsonResponse(payload, status=status)


def _read_json_body(request):
    if len(request.body) > 64 * 1024:
        raise ValueError("Request body is too large")
    return json.loads(request.body)


def _clean_prompt(raw_prompt):
    prompt = str(raw_prompt or "").strip()
    if not prompt:
        raise ValueError("prompt is required")
    if len(prompt) > MAX_PROMPT_CHARS:
        raise ValueError(f"prompt must be {MAX_PROMPT_CHARS} characters or fewer")
    return prompt


def _redact_for_log(value):
    text = str(value or "")
    secret_markers = ("sk-", "api_key", "apikey", "password", "token", "secret")
    if any(marker in text.lower() for marker in secret_markers):
        return "[redacted: possible secret]"
    if len(text) > MAX_LOG_CHARS:
        return text[:MAX_LOG_CHARS] + "... [truncated]"
    return text


def _get_client_ip(request):
    forwarded_for = request.META.get("HTTP_X_FORWARDED_FOR")
    if forwarded_for:
        return forwarded_for.split(",")[0].strip()
    return request.META.get("REMOTE_ADDR")


def _prompt_hash(prompt):
    return hashlib.sha256(prompt.encode("utf-8")).hexdigest()


def _write_audit_log(
    request,
    *,
    request_id,
    event_type,
    prompt,
    result,
    llm_name=None,
    llm_response=None,
    llm_error=None,
    forwarded_to_llm=False,
    proceeded_after_warning=False,
):
    return PromptLog.objects.create(
        request_id=request_id,
        event_type=event_type,
        prompt=_redact_for_log(prompt),
        prompt_length=len(prompt),
        prompt_hash=_prompt_hash(prompt),
        decision=result.decision,
        threat_level=result.threat_level,
        risk_score=result.risk_score,
        attack_types=result.attack_types,
        reasons=result.reasons,
        ai_reasoning=result.ai_reasoning,
        llm_used=llm_name if forwarded_to_llm else None,
        llm_response=_redact_for_log(llm_response),
        llm_error=_redact_for_log(llm_error),
        forwarded_to_llm=forwarded_to_llm,
        proceeded_after_warning=proceeded_after_warning,
        client_ip=_get_client_ip(request),
        user_agent=request.META.get("HTTP_USER_AGENT", "")[:1000],
        path=request.path,
        processing_time_ms=result.processing_time_ms,
    )


@require_http_methods(["POST"])
def analyze(request):
    try:
        body = _read_json_body(request)
        prompt = _clean_prompt(body.get("prompt"))
        request_id = str(uuid.uuid4())

        result = firewall.analyze(prompt)

        _write_audit_log(
            request,
            request_id=request_id,
            event_type=PromptLog.EVENT_ANALYZE,
            prompt=prompt,
            result=result,
        )

        return JsonResponse({
            "decision": result.decision,
            "threat_level": result.threat_level,
            "risk_score": result.risk_score,
            "attack_types": result.attack_types,
            "reasons": result.reasons,
            "ai_reasoning": result.ai_reasoning,
            "processing_time_ms": round(result.processing_time_ms, 1),
        })

    except json.JSONDecodeError:
        return _error_response("Invalid JSON", status=400)
    except ValueError as e:
        return _error_response(str(e), status=400)
    except Exception as e:
        return _error_response("Analysis failed", status=500, detail=e)


@require_http_methods(["POST"])
def firewall_view(request):
    try:
        body = _read_json_body(request)
        prompt = _clean_prompt(body.get("prompt"))
        request_id = str(uuid.uuid4())
        llm_name = str(body.get("llm", "ollama")).strip().lower()
        api_key = body.get("api_key", None)
        proceed_on_warn = bool(body.get("proceed_on_warn", False))

        if llm_name not in ALLOWED_LLMS:
            return _error_response("Unsupported LLM adapter", status=400)

        result = firewall.analyze(prompt)

        llm_response = None
        llm_error = None

        should_forward = result.decision == "ALLOW" or (
            result.decision == "WARN" and proceed_on_warn
        )

        if should_forward:
            try:
                adapter = get_adapter(llm_name)
                llm_response = adapter.send(prompt, api_key=api_key)
            except Exception as e:
                llm_error = str(e)

        if llm_error:
            event_type = PromptLog.EVENT_LLM_ERROR
        elif should_forward:
            event_type = PromptLog.EVENT_LLM_FORWARD
        else:
            event_type = PromptLog.EVENT_FIREWALL

        _write_audit_log(
            request,
            request_id=request_id,
            event_type=event_type,
            prompt=prompt,
            result=result,
            llm_name=llm_name,
            llm_response=llm_response,
            llm_error=llm_error,
            forwarded_to_llm=should_forward and llm_error is None,
            proceeded_after_warning=result.decision == "WARN" and should_forward,
        )

        response_data = {
            "decision": result.decision,
            "threat_level": result.threat_level,
            "risk_score": result.risk_score,
            "attack_types": result.attack_types,
            "reasons": result.reasons,
            "ai_reasoning": result.ai_reasoning,
            "llm_used": llm_name if should_forward else None,
            "llm_response": llm_response,
            "can_proceed": result.decision == "WARN",
            "proceeded_after_warning": result.decision == "WARN" and should_forward,
            "processing_time_ms": round(result.processing_time_ms, 1),
        }

        if result.decision != "ALLOW":
            response_data["block_reason"] = (
                ", ".join(result.attack_types) + " detected"
                if result.attack_types else "Risk score too high"
            )

        if llm_error:
            response_data["llm_error"] = llm_error

        return JsonResponse(response_data)

    except json.JSONDecodeError:
        return _error_response("Invalid JSON", status=400)
    except ValueError as e:
        return _error_response(str(e), status=400)
    except Exception as e:
        return _error_response("Firewall request failed", status=500, detail=e)
