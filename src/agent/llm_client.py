# -*- coding: utf-8 -*-
"""
Config-driven client for NVIDIA NIM (OpenAI-compatible) used by the Layer-3 analyst.

* Model chain from config — default ``nvidia/nemotron-3.5-lightning-30b-a3b`` (v5.1.0; was Ultra) then
  ``nvidia/nemotron-3-super-120b-a12b``; on HTTP 4xx/5xx, timeout or network error the next
  model is tried, and the caller falls back to the deterministic rule-based summary.
* Strict structured output via forced tool-calling.
* Injectable ``transport`` so CI runs against a mocked LLM (no key, no network).
* Latency, token and estimated-cost metrics exported on ``/metrics``.
* The API key is read from the environment only and is never logged.
"""
from __future__ import annotations

import json
import logging
import os
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Tuple

from src.obs import metrics as obs_metrics

logger = logging.getLogger("llm_client")

DEFAULT_BASE_URL = "https://integrate.api.nvidia.com/v1"
# v5.1.0: primary model is Nemotron 3.5 Lightning (id + forced tool-calling verified on the live NIM
# model list, 3.6 s per call). Ultra (27-46 s, timed out / 503 at the v5.0.0 release) is now an
# optional severity-5 escalation only.
LIGHTNING_MODEL = "nvidia/nemotron-3.5-lightning-30b-a3b"
ULTRA_MODEL = "nvidia/nemotron-3-ultra-550b-a55b"
DEFAULT_MODELS = LIGHTNING_MODEL


def _truthy(v: Any) -> bool:
    return str(v).strip().lower() in ("1", "true", "yes", "on")


@dataclass
class LLMConfig:
    base_url: str = DEFAULT_BASE_URL
    api_key: str = ""
    models: List[str] = field(default_factory=lambda: DEFAULT_MODELS.split(","))
    timeout_s: float = 90.0   # full structured analysis measured at 27-38s on Ultra
    temperature: float = 0.2
    max_tokens: int = 1500
    enable_thinking: bool = False
    price_in_per_1m: float = 0.0   # USD per 1M prompt tokens (0 = free tier)
    price_out_per_1m: float = 0.0  # USD per 1M completion tokens
    escalate_severity5: bool = False   # try the escalation model first for severity-5 incidents
    escalation_model: str = ULTRA_MODEL

    @classmethod
    def from_env(cls, section: Optional[Dict[str, Any]] = None) -> "LLMConfig":
        s = section or {}

        def pick(env: str, key: str, default: Any) -> Any:
            v = os.environ.get(env)
            if v not in (None, ""):
                return v
            v = s.get(key)
            return default if v in (None, "") else v

        # DDOS_LLM_MODELS / analyst.models = full chain; else NEMOTRON_MODEL = the primary model alone.
        models = pick("DDOS_LLM_MODELS", "models", os.environ.get("NEMOTRON_MODEL") or DEFAULT_MODELS)
        if isinstance(models, str):
            models = [m.strip() for m in models.split(",") if m.strip()]
        return cls(
            base_url=str(pick("DDOS_LLM_BASE_URL", "base_url", DEFAULT_BASE_URL)).rstrip("/"),
            api_key=os.environ.get("NVIDIA_API_KEY", ""),
            models=list(models),
            timeout_s=float(pick("DDOS_LLM_TIMEOUT", "timeout_s", 90.0)),
            temperature=float(pick("DDOS_LLM_TEMPERATURE", "temperature", 0.2)),
            max_tokens=int(pick("DDOS_LLM_MAX_TOKENS", "max_tokens", 1500)),
            enable_thinking=_truthy(pick("DDOS_LLM_ENABLE_THINKING", "enable_thinking", False)),
            price_in_per_1m=float(pick("DDOS_LLM_PRICE_IN_PER_1M", "price_in_per_1m", 0.0)),
            price_out_per_1m=float(pick("DDOS_LLM_PRICE_OUT_PER_1M", "price_out_per_1m", 0.0)),
            escalate_severity5=_truthy(pick("DDOS_LLM_ESCALATE_ULTRA", "escalate_severity5_to_ultra", False)),
            escalation_model=str(pick("DDOS_LLM_ESCALATION_MODEL", "escalation_model", ULTRA_MODEL)),
        )

    def public_view(self) -> Dict[str, Any]:
        """Config safe to show in the UI / logs (no key)."""
        return {"base_url": self.base_url, "models": self.models, "timeout_s": self.timeout_s,
                "enable_thinking": self.enable_thinking, "api_key_present": bool(self.api_key),
                "escalate_severity5": self.escalate_severity5, "escalation_model": self.escalation_model}


class LLMUnavailable(Exception):
    """Model could not be used (4xx/5xx, timeout, network). Caller tries the next model."""


Transport = Callable[[str, Dict[str, str], Dict[str, Any], float], Dict[str, Any]]


def _requests_transport(url: str, headers: Dict[str, str], body: Dict[str, Any], timeout: float) -> Dict[str, Any]:
    import requests  # local import keeps module import cheap in tests

    try:
        resp = requests.post(url, headers=headers, data=json.dumps(body), timeout=timeout)
    except requests.Timeout as e:
        raise LLMUnavailable("timeout") from e
    except requests.RequestException as e:
        raise LLMUnavailable(f"network:{type(e).__name__}") from e
    if resp.status_code >= 400:
        # Never echo the response body: it can contain account identifiers.
        raise LLMUnavailable(f"http_{resp.status_code}")
    return resp.json()


class LLMClient:
    def __init__(self, config: Optional[LLMConfig] = None, transport: Optional[Transport] = None):
        self.config = config or LLMConfig.from_env()
        self._transport = transport or _requests_transport

    @property
    def available(self) -> bool:
        return bool(self.config.api_key) or self._transport is not _requests_transport

    def _post(self, model: str, body: Dict[str, Any]) -> Dict[str, Any]:
        url = f"{self.config.base_url}/chat/completions"
        headers = {"Authorization": f"Bearer {self.config.api_key}", "Content-Type": "application/json",
                   "Accept": "application/json"}
        start = time.perf_counter()
        try:
            data = self._transport(url, headers, body, self.config.timeout_s)
        except LLMUnavailable as e:
            obs_metrics.LLM_REQUESTS.inc(model=model, outcome=str(e).split(":")[0])
            raise
        elapsed = time.perf_counter() - start
        obs_metrics.LLM_LATENCY_SUM.inc(elapsed, model=model)
        obs_metrics.LLM_LATENCY_COUNT.inc(model=model)
        usage = data.get("usage") or {}
        p_tok, c_tok = int(usage.get("prompt_tokens") or 0), int(usage.get("completion_tokens") or 0)
        obs_metrics.LLM_TOKENS.inc(p_tok, model=model, kind="prompt")
        obs_metrics.LLM_TOKENS.inc(c_tok, model=model, kind="completion")
        cost = p_tok / 1e6 * self.config.price_in_per_1m + c_tok / 1e6 * self.config.price_out_per_1m
        if cost:
            obs_metrics.LLM_COST.inc(cost, model=model)
        data["_latency_s"] = elapsed
        return data

    def _base_body(self, model: str, messages: List[Dict[str, Any]]) -> Dict[str, Any]:
        return {"model": model, "messages": messages, "temperature": self.config.temperature,
                "max_tokens": self.config.max_tokens,
                "chat_template_kwargs": {"enable_thinking": self.config.enable_thinking}}

    def call_tool(self, model: str, messages: List[Dict[str, Any]], tool: Dict[str, Any]) -> Tuple[Optional[Dict[str, Any]], float]:
        """Force a single tool call. Returns (arguments_dict_or_None, latency_s)."""
        body = self._base_body(model, messages)
        body["tools"] = [tool]
        body["tool_choice"] = {"type": "function", "function": {"name": tool["function"]["name"]}}
        data = self._post(model, body)
        msg = (data.get("choices") or [{}])[0].get("message") or {}
        args: Optional[Dict[str, Any]] = None
        for tc in msg.get("tool_calls") or []:
            raw = (tc.get("function") or {}).get("arguments")
            try:
                args = raw if isinstance(raw, dict) else json.loads(raw)
            except (TypeError, ValueError):
                args = None
            break
        if args is None and msg.get("content"):
            # Some deployments return the JSON in content instead of tool_calls.
            txt = msg["content"].strip().strip("`")
            if txt.lower().startswith("json"):
                txt = txt[4:]
            try:
                args = json.loads(txt)
            except ValueError:
                args = None
        obs_metrics.LLM_REQUESTS.inc(model=model, outcome="ok" if args is not None else "no_tool_call")
        return args, data.get("_latency_s", 0.0)

    def chat(self, model: str, messages: List[Dict[str, Any]]) -> str:
        data = self._post(model, self._base_body(model, messages))
        obs_metrics.LLM_REQUESTS.inc(model=model, outcome="ok")
        return ((data.get("choices") or [{}])[0].get("message") or {}).get("content") or ""
