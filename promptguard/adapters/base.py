class BaseLLMAdapter:
    def send(self, prompt: str, api_key: str = None) -> str:
        raise NotImplementedError(
            f"{self.__class__.__name__} must implement the send() method."
        )

    def name(self) -> str:
        return self.__class__.__name__