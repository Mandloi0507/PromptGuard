"""
Smoke tests for the LLM adapters.
"""

from promptguard.adapters import ADAPTER_REGISTRY, AnthropicAdapter, GeminiAdapter, OllamaAdapter, OpenAIAdapter, get_adapter

print("=" * 60)
print("  promptguard - Adapter Tests")
print("=" * 60)

all_passed = True


def check(label, passed, detail=""):
    global all_passed
    status = "PASSED" if passed else "FAILED"
    print(f"{status}  {label}")
    if detail:
        print(f"        {detail}")
    if not passed:
        all_passed = False


expected_names = ["ollama", "claude", "anthropic", "openai", "gpt", "gemini", "google"]
check(
    "Registry contains all adapter names",
    all(n in ADAPTER_REGISTRY for n in expected_names),
    f"Registry keys: {list(ADAPTER_REGISTRY.keys())}",
)

check("get_adapter('ollama') returns OllamaAdapter", isinstance(get_adapter("ollama"), OllamaAdapter))
check("get_adapter('claude') returns AnthropicAdapter", isinstance(get_adapter("claude"), AnthropicAdapter))
check("get_adapter('openai') returns OpenAIAdapter", isinstance(get_adapter("openai"), OpenAIAdapter))
check("get_adapter('gpt') also returns OpenAIAdapter", isinstance(get_adapter("gpt"), OpenAIAdapter))
check("get_adapter('gemini') returns GeminiAdapter", isinstance(get_adapter("gemini"), GeminiAdapter))
check("get_adapter('google') also returns GeminiAdapter", isinstance(get_adapter("google"), GeminiAdapter))

try:
    get_adapter("mistral")
    check("Unknown adapter raises ValueError", False)
except ValueError as e:
    check("Unknown adapter raises ValueError", True, str(e))

try:
    adapter = get_adapter("ollama")
    response = adapter.send("Hello")
    check("Ollama returns a response when running", isinstance(response, str))
except ConnectionError:
    check("Ollama raises ConnectionError when offline", True)
except Exception as e:
    check("Ollama returns response or clean offline error", False, f"Wrong exception type: {type(e).__name__}: {e}")

try:
    adapter = get_adapter("claude")
    adapter.send("Hello", api_key=None)
    check("Claude raises ValueError with no API key", False)
except ValueError as e:
    check("Claude raises ValueError with no API key", True, str(e))

try:
    adapter = get_adapter("gemini")
    adapter.send("Hello", api_key=None)
    check("Gemini raises ValueError with no API key", False)
except ValueError as e:
    check("Gemini raises ValueError with no API key", True, str(e))

check("OllamaAdapter.name() returns string", isinstance(OllamaAdapter().name(), str), OllamaAdapter().name())
check("AnthropicAdapter.name() returns string", isinstance(AnthropicAdapter().name(), str), AnthropicAdapter().name())
check("GeminiAdapter.name() returns string", isinstance(GeminiAdapter().name(), str), GeminiAdapter().name())

print()
print("All tests passed!" if all_passed else "Some tests failed")
