import json
import os
import urllib.error
import urllib.request

from .base import BaseLLMAdapter


class GeminiAdapter(BaseLLMAdapter):

    def __init__(self, model: str = "gemini-2.5-flash"):
        self.model = model
        self.api_url = (
            "https://generativelanguage.googleapis.com/v1beta/"
            f"models/{self.model}:generateContent"
        )

    def name(self) -> str:
        return f"Gemini ({self.model})"

    def send(self, prompt: str, api_key: str = None) -> str:
        resolved_key = api_key or os.environ.get("GEMINI_API_KEY") or os.environ.get("GOOGLE_API_KEY")
        if not resolved_key:
            raise ValueError(
                "No Gemini API key provided. "
                "Pass it as api_key=... or set the GEMINI_API_KEY environment variable."
            )

        payload = {
            "contents": [
                {
                    "role": "user",
                    "parts": [{"text": prompt}],
                }
            ]
        }
        data = json.dumps(payload).encode("utf-8")
        request = urllib.request.Request(
            self.api_url,
            data=data,
            headers={
                "Content-Type": "application/json",
                "x-goog-api-key": resolved_key,
            },
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=60) as response:
                result = json.loads(response.read().decode("utf-8"))
                parts = result["candidates"][0]["content"].get("parts", [])
                text_parts = [part.get("text", "") for part in parts if part.get("text")]
                return "\n".join(text_parts).strip()
        except urllib.error.HTTPError as e:
            body = e.read().decode("utf-8")
            raise Exception(f"Gemini API error {e.code}: {body}")
        except urllib.error.URLError as e:
            raise ConnectionError(f"Could not reach Gemini API: {e}")
        except Exception as e:
            raise Exception(f"Gemini request failed: {e}")
