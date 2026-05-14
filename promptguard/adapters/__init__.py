from .base import BaseLLMAdapter
from .ollama import OllamaAdapter
from .anthropic import AnthropicAdapter
from .openai import OpenAIAdapter
from .gemini import GeminiAdapter

ADAPTER_REGISTRY = {
    "ollama":     OllamaAdapter,
    "claude":     AnthropicAdapter,
    "anthropic":  AnthropicAdapter,
    "openai":     OpenAIAdapter,
    "gpt":        OpenAIAdapter,
    "gemini":     GeminiAdapter,
    "google":     GeminiAdapter,
}

def get_adapter(name: str) -> BaseLLMAdapter:
    name_lower = name.lower().strip()
    adapter_class = ADAPTER_REGISTRY.get(name_lower)
    if adapter_class is None:
        available = ", ".join(ADAPTER_REGISTRY.keys())
        raise ValueError(
            f"Unknown LLM adapter: '{name}'. "
            f"Available options: {available}"
        )
    return adapter_class()
