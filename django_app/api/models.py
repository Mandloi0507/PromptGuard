from django.db import models

class PromptLog(models.Model):
    EVENT_ANALYZE = "ANALYZE"
    EVENT_FIREWALL = "FIREWALL"
    EVENT_LLM_FORWARD = "LLM_FORWARD"
    EVENT_LLM_ERROR = "LLM_ERROR"

    EVENT_CHOICES = [
        (EVENT_ANALYZE, "Analyze only"),
        (EVENT_FIREWALL, "Firewall decision"),
        (EVENT_LLM_FORWARD, "Forwarded to LLM"),
        (EVENT_LLM_ERROR, "LLM adapter error"),
    ]

    request_id = models.CharField(max_length=36, db_index=True, blank=True)
    session_id = models.CharField(max_length=64, db_index=True, blank=True, default="")
    event_type = models.CharField(max_length=20, choices=EVENT_CHOICES, default=EVENT_ANALYZE)
    prompt = models.TextField()
    prompt_length = models.PositiveIntegerField(default=0)
    prompt_hash = models.CharField(max_length=64, db_index=True, blank=True)
    decision = models.CharField(max_length=10)
    threat_level = models.CharField(max_length=10)
    risk_score = models.IntegerField()
    attack_types = models.JSONField(default=list)
    reasons = models.JSONField(default=list)
    ai_reasoning = models.TextField(blank=True, default="")
    llm_used = models.CharField(max_length=50, blank=True, null=True)
    llm_response = models.TextField(blank=True, null=True)
    llm_error = models.TextField(blank=True, null=True)
    forwarded_to_llm = models.BooleanField(default=False)
    proceeded_after_warning = models.BooleanField(default=False)
    client_ip = models.GenericIPAddressField(blank=True, null=True)
    user_agent = models.TextField(blank=True)
    path = models.CharField(max_length=120, blank=True)
    processing_time_ms = models.FloatField(default=0.0)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['event_type', '-created_at']),
            models.Index(fields=['decision', '-created_at']),
            models.Index(fields=['forwarded_to_llm', '-created_at']),
        ]

    def __str__(self):
        return f"[{self.event_type}:{self.decision}] {self.prompt[:60]}"
