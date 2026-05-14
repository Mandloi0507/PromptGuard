from django.db import models

class PromptLog(models.Model):
    prompt = models.TextField()
    decision = models.CharField(max_length=10)
    threat_level = models.CharField(max_length=10)
    risk_score = models.IntegerField()
    attack_types = models.JSONField(default=list)
    reasons = models.JSONField(default=list)
    semantic_score = models.FloatField(default=0.0)
    llm_used = models.CharField(max_length=50, blank=True, null=True)
    llm_response = models.TextField(blank=True, null=True)
    processing_time_ms = models.FloatField(default=0.0)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['-created_at']

    def __str__(self):
        return f"[{self.decision}] {self.prompt[:60]}"