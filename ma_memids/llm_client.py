from __future__ import annotations

import json
import os
from abc import ABC, abstractmethod
from typing import Dict, List, Optional

import httpx
from dotenv import load_dotenv


class BaseLLMClient(ABC):
    @abstractmethod
    def chat(self, messages: List[Dict[str, str]], temperature: float = 0.2) -> str:
        raise NotImplementedError

    @abstractmethod
    def model_name(self) -> str:
        raise NotImplementedError


class NullLLMClient(BaseLLMClient):
    """Offline fallback client used when no API key is configured."""

    def chat(self, messages: List[Dict[str, str]], temperature: float = 0.2) -> str:
        _ = temperature
        last = messages[-1]["content"] if messages else ""
        if "输出 JSON" in last or "output JSON" in last.lower():
            return json.dumps(
                {
                    "intent": "Detect suspicious exploit-like traffic pattern",
                    "keywords": ["suspicious", "exploit", "payload"],
                    "tactics": ["T1190"],
                },
                ensure_ascii=False,
            )
        return ""

    def model_name(self) -> str:
        return "null-offline"


class OpenAICompatibleClient(BaseLLMClient):
    def __init__(self, api_key: str, model: str, base_url: str):
        self._api_key = api_key
        self._model = model
        self._base_url = base_url.rstrip("/")
        self._http = httpx.Client(timeout=120.0)

    def chat(self, messages: List[Dict[str, str]], temperature: float = 0.2) -> str:
        payload = {
            "model": self._model,
            "messages": messages,
            "temperature": temperature,
            "max_tokens": 2048,
        }
        headers = {
            "Authorization": f"Bearer {self._api_key}",
            "Content-Type": "application/json",
        }
        resp = self._http.post(f"{self._base_url}/chat/completions", headers=headers, json=payload)
        resp.raise_for_status()
        data = resp.json()
        return data["choices"][0]["message"]["content"]

    def model_name(self) -> str:
        return self._model


def create_llm_client(model: Optional[str] = None) -> BaseLLMClient:
    # Keep behavior aligned with GRIDAI: read .env before resolving provider keys.
    load_dotenv()
    model = model or os.getenv("LLM_MODEL", "gpt-4.1")
    model_lower = model.lower()

    if model_lower.startswith("deepseek"):
        api_key = os.getenv("DEEPSEEK_API_KEY")
        base_url = os.getenv("DEEPSEEK_BASE_URL", "https://api.deepseek.com/v1")
    elif model_lower.startswith("glm"):
        api_key = os.getenv("ZHIPU_API_KEY")
        base_url = os.getenv("ZHIPU_BASE_URL", "https://open.bigmodel.cn/api/paas/v4")
    else:
        api_key = os.getenv("OPENAI_API_KEY")
        base_url = os.getenv("OPENAI_BASE_URL", "https://api.openai.com/v1")

    if not api_key:
        return NullLLMClient()

    return OpenAICompatibleClient(api_key=api_key, model=model, base_url=base_url)
