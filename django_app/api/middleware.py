# ============================================================
# middleware.py — Rate Limiting Middleware for PromptGuard API
# ============================================================
# Sliding-window rate limiter using Django's cache framework.
# Protects /api/* endpoints from abuse (cost attacks, timing).
# ============================================================

import time

from django.conf import settings
from django.core.cache import cache
from django.http import JsonResponse


class RateLimitMiddleware:
    """
    Per-IP sliding-window rate limiter for API endpoints.

    Only applies to POST requests under /api/ paths. Uses Django's
    cache backend for storage (LocMemCache in dev, Redis in prod).

    Config via settings:
        RATE_LIMIT_PER_MINUTE  — max requests per IP per minute (default: 30)
    """

    def __init__(self, get_response):
        self.get_response = get_response
        self.limit = getattr(settings, "RATE_LIMIT_PER_MINUTE", 30)
        self.window = 60  # seconds

    def __call__(self, request):
        # Only rate-limit POST requests to API endpoints
        if not (request.method == "POST" and request.path.startswith("/api/")):
            return self.get_response(request)

        client_ip = self._get_client_ip(request)
        cache_key = f"ratelimit:{client_ip}"

        # Fetch the sliding window log from cache
        now = time.time()
        request_log = cache.get(cache_key, [])

        # Prune entries older than the window
        cutoff = now - self.window
        request_log = [ts for ts in request_log if ts > cutoff]

        if len(request_log) >= self.limit:
            # Calculate retry-after from the oldest entry in the window
            oldest = min(request_log) if request_log else now
            retry_after = int(self.window - (now - oldest)) + 1

            response = JsonResponse(
                {
                    "error": "Rate limit exceeded. Please slow down.",
                    "retry_after_seconds": retry_after,
                },
                status=429,
            )
            response["Retry-After"] = str(retry_after)
            response["X-RateLimit-Limit"] = str(self.limit)
            response["X-RateLimit-Remaining"] = "0"
            return response

        # Record this request
        request_log.append(now)
        cache.set(cache_key, request_log, timeout=self.window + 10)

        # Process the request and add rate-limit headers
        response = self.get_response(request)
        remaining = max(0, self.limit - len(request_log))
        response["X-RateLimit-Limit"] = str(self.limit)
        response["X-RateLimit-Remaining"] = str(remaining)
        return response

    @staticmethod
    def _get_client_ip(request):
        forwarded_for = request.META.get("HTTP_X_FORWARDED_FOR")
        if forwarded_for:
            return forwarded_for.split(",")[0].strip()
        return request.META.get("REMOTE_ADDR", "unknown")
