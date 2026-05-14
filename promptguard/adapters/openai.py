import json
import os
import urllib.request
import urllib.error
from .base import BaseLLMAdapter


class OpenAIAdapter(BaseLLMAdapter):

    def __init__(self, model: str = "gpt-3.5-turbo"):
        self.model = model
        self.api_url = "https://api.openai.com/v1/chat/completions"

    def name(self) -> str:
        return f"OpenAI ({self.model})"

    def send(self, prompt: str, api_key: str = None) -> str:
        resolved_key = api_key or os.environ.get("OPENAI_API_KEY")
        if not resolved_key:
            raise ValueError(
                "No OpenAI API key provided. "
                "Pass it as api_key=... or set the OPENAI_API_KEY environment variable."
            )
        payload = {
            "model": self.model,
            "messages": [{"role": "user", "content": prompt}],
            "max_tokens": 1024,
        }
        data = json.dumps(payload).encode("utf-8")
        request = urllib.request.Request(
            self.api_url,
            data=data,
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {resolved_key}",
            },
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=30) as response:
                result = json.loads(response.read().decode("utf-8"))
                return result["choices"][0]["message"]["content"].strip()
        except urllib.error.HTTPError as e:
            body = e.read().decode("utf-8")
            raise Exception(f"OpenAI API error {e.code}: {body}")
        except urllib.error.URLError as e:
            raise ConnectionError(f"Could not reach OpenAI API: {e}")
        except Exception as e:
            raise Exception(f"OpenAI request failed: {e}")