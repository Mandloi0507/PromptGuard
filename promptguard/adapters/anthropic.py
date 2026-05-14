import json
import os
import urllib.request
import urllib.error
from .base import BaseLLMAdapter


class AnthropicAdapter(BaseLLMAdapter):

    def __init__(self, model: str = "claude-3-haiku-20240307"):
        self.model = model
        self.api_url = "https://api.anthropic.com/v1/messages"

    def name(self) -> str:
        return f"Claude ({self.model})"

    def send(self, prompt: str, api_key: str = None) -> str:
        resolved_key = api_key or os.environ.get("ANTHROPIC_API_KEY")
        if not resolved_key:
            raise ValueError(
                "No Anthropic API key provided. "
                "Pass it as api_key=... or set the ANTHROPIC_API_KEY environment variable."
            )
        payload = {
            "model": self.model,
            "max_tokens": 1024,
            "messages": [{"role": "user", "content": prompt}],
        }
        data = json.dumps(payload).encode("utf-8")
        request = urllib.request.Request(
            self.api_url,
            data=data,
            headers={
                "Content-Type": "application/json",
                "x-api-key": resolved_key,
                "anthropic-version": "2023-06-01",
            },
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=30) as response:
                result = json.loads(response.read().decode("utf-8"))
                return result["content"][0]["text"].strip()
        except urllib.error.HTTPError as e:
            body = e.read().decode("utf-8")
            raise Exception(f"Anthropic API error {e.code}: {body}")
        except urllib.error.URLError as e:
            raise ConnectionError(f"Could not reach Anthropic API: {e}")
        except Exception as e:
            raise Exception(f"Anthropic request failed: {e}")