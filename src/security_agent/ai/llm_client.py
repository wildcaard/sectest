"""LLM provider abstraction for Anthropic, OpenAI, and Ollama."""

import logging
import os
from abc import ABC, abstractmethod
from typing import Optional

logger = logging.getLogger("security_agent")


class LLMClient(ABC):
    """Abstract client for LLM completion. All providers implement this interface."""

    @abstractmethod
    async def complete(self, prompt: str, max_tokens: int) -> str:
        """Send prompt to the model and return the generated text."""
        pass


class AnthropicLLMClient(LLMClient):
    """Anthropic (Claude) API client using AsyncAnthropic."""

    def __init__(self, api_key: str, model: str):
        self._api_key = api_key
        self._model = model
        self._client = None

    def _get_client(self):
        if self._client is None:
            from anthropic import AsyncAnthropic
            self._client = AsyncAnthropic(api_key=self._api_key)
        return self._client

    async def complete(self, prompt: str, max_tokens: int) -> str:
        client = self._get_client()
        response = await client.messages.create(
            model=self._model,
            max_tokens=max_tokens,
            messages=[{"role": "user", "content": prompt}],
        )
        return response.content[0].text


class OpenAILLMClient(LLMClient):
    """OpenAI API client using AsyncOpenAI."""

    def __init__(self, api_key: str, model: str):
        self._api_key = api_key
        self._model = model
        self._client = None

    def _get_client(self):
        if self._client is None:
            from openai import AsyncOpenAI
            self._client = AsyncOpenAI(api_key=self._api_key)
        return self._client

    async def complete(self, prompt: str, max_tokens: int) -> str:
        client = self._get_client()
        response = await client.chat.completions.create(
            model=self._model,
            messages=[{"role": "user", "content": prompt}],
            max_tokens=max_tokens,
        )
        return response.choices[0].message.content or ""


class OllamaLLMClient(LLMClient):
    """Ollama local API client (HTTP POST to /api/chat)."""

    def __init__(self, base_url: str, model: str):
        self._base_url = base_url.rstrip("/")
        self._model = model

    async def complete(self, prompt: str, max_tokens: int) -> str:
        import httpx
        url = f"{self._base_url}/api/chat"
        payload = {
            "model": self._model,
            "messages": [{"role": "user", "content": prompt}],
            "stream": False,
        }
        async with httpx.AsyncClient(timeout=120.0) as client:
            response = await client.post(url, json=payload)
            response.raise_for_status()
            data = response.json()
        message = data.get("message") or {}
        return message.get("content", "")


def get_llm_client(config: dict) -> Optional[LLMClient]:
    """Build an LLM client from config. Returns None if provider is disabled or misconfigured.

    Reads config["ai"] for: provider, model, max_tokens, base_url (Ollama only).
    Env: ANTHROPIC_API_KEY (anthropic), OPENAI_API_KEY (openai). Ollama needs no key.
    """
    ai = config.get("ai", {})
    if not ai.get("enabled", True):
        return None

    provider = (ai.get("provider") or "anthropic").lower().strip()
    model = ai.get("model") or "claude-sonnet-4-20250514"

    if provider == "anthropic":
        api_key = os.environ.get("ANTHROPIC_API_KEY")
        if not api_key:
            logger.warning("ANTHROPIC_API_KEY not set. AI disabled.")
            return None
        try:
            return AnthropicLLMClient(api_key=api_key, model=model)
        except Exception as e:
            logger.warning(f"Failed to initialize Anthropic client: {e}")
            return None

    if provider == "openai":
        api_key = os.environ.get("OPENAI_API_KEY")
        if not api_key:
            logger.warning("OPENAI_API_KEY not set. AI disabled.")
            return None
        try:
            return OpenAILLMClient(api_key=api_key, model=model)
        except Exception as e:
            logger.warning(f"Failed to initialize OpenAI client: {e}")
            return None

    if provider == "ollama":
        base_url = ai.get("base_url") or "http://localhost:11434"
        try:
            return OllamaLLMClient(base_url=base_url, model=model)
        except Exception as e:
            logger.warning(f"Failed to initialize Ollama client: {e}")
            return None

    logger.warning(f"Unknown AI provider: {provider}. Supported: anthropic, openai, ollama.")
    return None
