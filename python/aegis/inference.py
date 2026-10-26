"""Inference budget and a vLLM client.

Resident agent contexts have to fit in three limits at once: vLLM's
`max_model_len`, the KV-cache token budget, and `max_num_seqs`. The local
backend returns a seed-stable completion so workflows can be traced without a
GPU. `VllmClient` calls the OpenAI-compatible server vLLM exposes.
"""

from __future__ import annotations

import hashlib
import json
import urllib.request
from dataclasses import dataclass


@dataclass(frozen=True)
class ModelBudget:
    max_model_len: int
    kv_token_budget: int
    max_num_seqs: int

    def resident_slots(self, context_tokens: int) -> int:
        if context_tokens <= 0 or context_tokens > self.max_model_len:
            raise ValueError("context does not fit in max_model_len")
        return min(self.max_num_seqs, self.kv_token_budget // context_tokens)


@dataclass(frozen=True)
class Completion:
    text: str
    seed: int
    model: str
    prompt_sha256: str


class LocalDeterministicLM:
    def complete(self, *, model: str, prompt: str, seed: int, max_tokens: int = 64) -> Completion:
        digest = hashlib.sha256(f"{seed}\n{prompt}".encode()).hexdigest()
        width = max(1, min(max_tokens, 32))
        return Completion(text=digest[:width], seed=seed, model=model, prompt_sha256=digest)


class VllmClient:
    def __init__(self, base_url: str, timeout: float = 60.0):
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout

    def max_model_len(self) -> int | None:
        payload = self._request("GET", "/v1/models")
        models = payload.get("data") or []
        if not models:
            return None
        value = models[0].get("max_model_len")
        return None if value is None else int(value)

    def budget(self, *, kv_token_budget: int, max_num_seqs: int) -> ModelBudget:
        max_model_len = self.max_model_len()
        if max_model_len is None:
            raise RuntimeError("vLLM server did not report max_model_len")
        return ModelBudget(
            max_model_len=max_model_len,
            kv_token_budget=kv_token_budget,
            max_num_seqs=max_num_seqs,
        )

    def complete(self, *, model: str, prompt: str, seed: int, max_tokens: int = 64) -> Completion:
        payload = self._request(
            "POST",
            "/v1/completions",
            {
                "model": model,
                "prompt": prompt,
                "max_tokens": max_tokens,
                "temperature": 0,
                "seed": seed,
            },
        )
        text = payload["choices"][0]["text"]
        digest = hashlib.sha256(prompt.encode()).hexdigest()
        return Completion(text=text, seed=seed, model=model, prompt_sha256=digest)

    def _request(self, method: str, path: str, body: dict | None = None) -> dict:
        data = None if body is None else json.dumps(body).encode()
        request = urllib.request.Request(
            self.base_url + path,
            data=data,
            method=method,
            headers={"Content-Type": "application/json"},
        )
        with urllib.request.urlopen(request, timeout=self.timeout) as response:
            return json.loads(response.read().decode())
