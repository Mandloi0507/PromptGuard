import json
import urllib.request
import urllib.error
from .base import BaseLLMAdapter


class OllamaAdapter(BaseLLMAdapter):

    def __init__(self, model: str = "llama3"):
        self.model = model
        self.base_url = "http://localhost:11434"

    def name(self) -> str:
        return f"Ollama ({self.model})"

    def send(self, prompt: str, api_key: str = None) -> str:
        url = f"{self.base_url}/api/generate"
        payload = {
            "model": self.model,
            "prompt": prompt,
            "stream": False,
        }
        data = json.dumps(payload).encode("utf-8")
        request = urllib.request.Request(
            url,
            data=data,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=60) as response:
                result = json.loads(response.read().decode("utf-8"))
                return result.get("response", "").strip()
        except urllib.error.URLError as e:
            raise ConnectionError(
                f"Could not connect to Ollama at {self.base_url}.\n"
                f"Make sure Ollama is running.\n"
                f"Original error: {e}"
            )
        except Exception as e:
            raise Exception(f"Ollama request failed: {e}")