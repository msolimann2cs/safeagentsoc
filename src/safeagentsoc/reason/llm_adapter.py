from __future__ import annotations

from abc import ABC, abstractmethod
from datetime import UTC, datetime
import json
import os
from time import sleep
from typing import Any
from urllib import error, request

from safeagentsoc.reason.schema_validator import confidence_label


class LLMProvider(ABC):
    @abstractmethod
    def generate_hypotheses(self, prompt: dict[str, Any]) -> dict[str, Any]:
        ...

    def provider_diagnostics(self) -> dict[str, Any]:
        return {"provider": self.__class__.__name__}


class MockLLMProvider(LLMProvider):
    def provider_diagnostics(self) -> dict[str, Any]:
        return {"provider": "mock", "network_required": False}

    def generate_hypotheses(self, prompt: dict[str, Any]) -> dict[str, Any]:
        context = prompt["provider_payload"]["case_context"]
        evidence_ids = context.get("evidence_ids") or []
        timeline = context.get("observed_timeline") or []
        alert_uids = sorted({alert_uid for step in timeline for alert_uid in (step.get("alert_uids") or [])})
        techniques = sorted({item.get("technique_id") for item in context.get("observed_technique_chain") or [] if item.get("technique_id")})
        tactic_mappings = context.get("mitre_tactic_mappings") or []
        missing = context.get("missing_evidence") or []
        checks = normalize_checks(context.get("recommended_investigation_checks") or [])
        hypotheses = [
            build_mock_hypothesis(
                "H1",
                title=primary_title(context),
                description=clean_primary_description(context),
                evidence_ids=evidence_ids[:8],
                alert_uids=alert_uids[:8],
                techniques=techniques[:6],
                tactic_mappings=tactic_mappings[:10],
                observed_facts=[step.get("evidence_summary") for step in timeline[:4] if step.get("evidence_summary")],
                inferred_facts=[item.get("reason") for item in context.get("inferred_relationships") or [] if item.get("reason")][:3],
                missing=missing[:5],
                checks=checks[:5],
                score=0.78 if techniques else 0.54,
            ),
            build_mock_hypothesis(
                "H2",
                title="Administrative or benign activity requiring validation",
                description="A non-malicious explanation remains possible if the activity aligns with expected administration, testing, or maintenance. Validate ownership, timing, and change records before treating this as malicious.",
                evidence_ids=evidence_ids[:5],
                alert_uids=alert_uids[:5],
                techniques=techniques[:4],
                tactic_mappings=tactic_mappings[:8],
                observed_facts=[context.get("safe_conclusion")],
                inferred_facts=[],
                missing=missing[:6],
                checks=checks[:6],
                score=0.62,
            ),
        ]
        if "telemetry_backlog" in str(context.get("safe_conclusion", "")).lower() or "backlog" in str(context.get("case_title", "")).lower():
            hypotheses.append(
                build_mock_hypothesis(
                    "H3",
                    title="Backlog telemetry review rather than confirmed intrusion",
                    description="The evidence appears suitable for backlog or repeated telemetry review and should not be treated as a confirmed intrusion chain.",
                    evidence_ids=evidence_ids[:6],
                    alert_uids=alert_uids[:6],
                    techniques=techniques[:4],
                    tactic_mappings=tactic_mappings[:8],
                    observed_facts=[step.get("evidence_summary") for step in timeline[:3] if step.get("evidence_summary")],
                    inferred_facts=[],
                    missing=missing[:5],
                    checks=checks[:5],
                    score=0.58,
                )
            )
        return {
            "case_id": context["case_id"],
            "provider": "mock",
            "model": "mock-deterministic-v1",
            "generated_at_utc": datetime.now(UTC).isoformat(),
            "hypotheses": hypotheses,
        }


class OpenAIResponsesProvider(LLMProvider):
    def __init__(
        self,
        *,
        api_key: str | None = None,
        model: str | None = None,
        base_url: str | None = None,
        timeout_seconds: int | None = None,
        reasoning_effort: str | None = None,
        verbosity: str | None = None,
        max_output_tokens: int | None = None,
    ) -> None:
        self.api_key = api_key or os.environ.get("OPENAI_API_KEY")
        self.model = model or os.environ.get("SAFEAGENTSOC_LLM_MODEL")
        self.base_url = (base_url or os.environ.get("SAFEAGENTSOC_LLM_BASE_URL") or "https://api.openai.com/v1").rstrip("/")
        self.timeout_seconds = timeout_seconds or int(os.environ.get("SAFEAGENTSOC_LLM_TIMEOUT_SECONDS", "60"))
        self.reasoning_effort = reasoning_effort or os.environ.get("SAFEAGENTSOC_LLM_REASONING_EFFORT") or "minimal"
        self.verbosity = verbosity or os.environ.get("SAFEAGENTSOC_LLM_VERBOSITY") or "low"
        self.max_output_tokens = max_output_tokens or int(os.environ.get("SAFEAGENTSOC_LLM_MAX_OUTPUT_TOKENS", "4096"))
        self.max_retries = int(os.environ.get("SAFEAGENTSOC_LLM_MAX_RETRIES", "2"))
        self.retry_backoff_seconds = float(os.environ.get("SAFEAGENTSOC_LLM_RETRY_BACKOFF_SECONDS", "1.5"))
        if not self.api_key:
            raise RuntimeError("OPENAI_API_KEY is required for SAFEAGENTSOC_LLM_PROVIDER=openai")
        if not self.model:
            raise RuntimeError("SAFEAGENTSOC_LLM_MODEL is required for SAFEAGENTSOC_LLM_PROVIDER=openai")

    def provider_diagnostics(self) -> dict[str, Any]:
        return {
            "provider": "openai",
            "model": self.model,
            "base_url": self.base_url,
            "timeout_seconds": self.timeout_seconds,
            "reasoning_effort": self.reasoning_effort,
            "verbosity": self.verbosity,
            "max_output_tokens": self.max_output_tokens,
            "max_retries": self.max_retries,
            "retry_backoff_seconds": self.retry_backoff_seconds,
            "api_key_present": bool(self.api_key),
            "api_key_preview": mask_secret(self.api_key),
        }

    def generate_hypotheses(self, prompt: dict[str, Any]) -> dict[str, Any]:
        payload = {
            "model": self.model,
            "input": [
                {"role": "system", "content": prompt["provider_payload"]["system"]},
                {"role": "developer", "content": prompt["provider_payload"]["developer"]},
                {
                    "role": "user",
                    "content": "Return JSON only for this SafeAgentSOC case:\n"
                    + json.dumps(prompt["provider_payload"]["case_context"], sort_keys=True, ensure_ascii=False),
                },
            ],
            "tools": [],
            "reasoning": {"effort": self.reasoning_effort},
            "max_output_tokens": self.max_output_tokens,
            "text": {
                "verbosity": self.verbosity,
                "format": {
                    "type": "json_schema",
                    "name": "safeagentsoc_hypothesis_response",
                    "strict": True,
                    "schema": openai_hypothesis_schema(),
                }
            },
        }
        last_parse_error: Exception | None = None
        attempts = max(1, self.max_retries + 1)
        for attempt in range(1, attempts + 1):
            body = self._post_with_retries(payload)
            text = extract_output_text(body)
            try:
                result = parse_json_response_text(text)
            except Exception as exc:
                last_parse_error = exc
                if attempt < attempts:
                    sleep(self.retry_backoff_seconds * attempt)
                    continue
                raise RuntimeError(f"OpenAI-compatible provider returned non-parseable JSON output: {exc}") from exc
            result["provider"] = "openai"
            result["model"] = self.model
            result.setdefault("generated_at_utc", datetime.now(UTC).isoformat())
            return result
        if last_parse_error is None:
            raise RuntimeError("OpenAI-compatible provider returned no parseable output.")
        raise RuntimeError(f"OpenAI-compatible provider returned non-parseable JSON output: {last_parse_error}")

    def preflight(self) -> dict[str, Any]:
        payload = {
            "model": self.model,
            "input": [
                {"role": "system", "content": "Return JSON only."},
                {"role": "user", "content": "Return {\"status\":\"ok\"}."},
            ],
            "tools": [],
            "reasoning": {"effort": self.reasoning_effort},
            "max_output_tokens": 256,
            "text": {
                "verbosity": "low",
                "format": {
                    "type": "json_schema",
                    "name": "safeagentsoc_preflight",
                    "strict": True,
                    "schema": {
                        "type": "object",
                        "additionalProperties": False,
                        "required": ["status"],
                        "properties": {"status": {"type": "string"}},
                    },
                }
            },
        }
        body = self._post_responses(payload)
        return {"ok": True, "response_id": body.get("id"), "output_text": extract_output_text(body)}

    def _post_responses(self, payload: dict[str, Any]) -> dict[str, Any]:
        data = json.dumps(payload).encode("utf-8")
        req = request.Request(
            f"{self.base_url}/responses",
            data=data,
            headers={
                "Authorization": f"Bearer {self.api_key}",
                "Content-Type": "application/json",
            },
            method="POST",
        )
        with request.urlopen(req, timeout=self.timeout_seconds) as response:
            body_text = response.read().decode("utf-8", errors="replace")
        try:
            decoded = json.loads(body_text)
            if isinstance(decoded, dict):
                return decoded
            raise ValueError("HTTP response top-level JSON value is not an object.")
        except json.JSONDecodeError:
            # Rarely, transient transport truncation leaves trailing garbage; salvage the first JSON object.
            decoder = json.JSONDecoder()
            decoded, _index = decoder.raw_decode(body_text.lstrip())
            if isinstance(decoded, dict):
                return decoded
            raise ValueError("HTTP response raw-decoded JSON value is not an object.")

    def _post_with_retries(self, payload: dict[str, Any]) -> dict[str, Any]:
        last_error: Exception | None = None
        attempts = max(1, self.max_retries + 1)
        for attempt in range(1, attempts + 1):
            try:
                return self._post_responses(payload)
            except error.HTTPError as exc:
                detail = exc.read().decode("utf-8", errors="replace")
                last_error = RuntimeError(f"OpenAI-compatible provider failed: {exc.code} {detail}")
                if exc.code not in {408, 409, 429, 500, 502, 503, 504} or attempt == attempts:
                    raise last_error from exc
            except (error.URLError, TimeoutError, OSError) as exc:
                last_error = RuntimeError(f"OpenAI-compatible provider request failed: {exc}")
                if attempt == attempts:
                    raise last_error from exc
            except ValueError as exc:
                # Includes transient JSON decode failures on provider HTTP body parsing.
                last_error = RuntimeError(f"OpenAI-compatible provider response parse failed: {exc}")
                if attempt == attempts:
                    raise last_error from exc
            sleep(self.retry_backoff_seconds * attempt)
        if last_error is None:
            raise RuntimeError("OpenAI-compatible provider request failed with unknown error.")
        raise last_error


def provider_from_env(provider_name: str | None = None) -> LLMProvider:
    provider = (provider_name or os.environ.get("SAFEAGENTSOC_LLM_PROVIDER") or "openai").lower()
    if provider == "mock":
        return MockLLMProvider()
    if provider == "openai":
        return OpenAIResponsesProvider()
    raise ValueError(f"Unsupported LLM provider: {provider}")


def mask_secret(value: str | None) -> str:
    if not value:
        return "missing"
    if len(value) <= 12:
        return "***"
    return f"{value[:7]}...{value[-4:]}"


def build_mock_hypothesis(
    hypothesis_id: str,
    *,
    title: str,
    description: str,
    evidence_ids: list[str],
    alert_uids: list[str],
    techniques: list[str],
    tactic_mappings: list[dict[str, str]],
    observed_facts: list[str],
    inferred_facts: list[str],
    missing: list[dict[str, Any]],
    checks: list[str],
    score: float,
) -> dict[str, Any]:
    score = round(max(0.0, min(score, 1.0)), 2)
    return {
        "hypothesis_id": hypothesis_id,
        "title": title[:140],
        "description": description[:600],
        "claim_type": "evidence_grounded",
        "confidence_score": score,
        "confidence_label": confidence_label(score),
        "supporting_evidence_ids": evidence_ids[:10],
        "supporting_alert_uids": alert_uids[:10],
        "mitre_techniques": sorted(set(techniques[:8])),
        "mitre_tactic_mappings": tactic_mappings[:12],
        "observed_facts": [item for item in observed_facts if item][:8],
        "inferred_facts": [item for item in inferred_facts if item][:6],
        "missing_evidence": [
            {
                "missing_evidence_type": row.get("missing_evidence_type"),
                "status": row.get("status"),
                "reason": row.get("reason"),
            }
            for row in missing[:8]
        ],
        "recommended_checks": checks[:8],
        "forbidden_claims_respected": True,
        "limitations": ["Generated by constrained Phase 7 hypothesis engine; not a response decision."],
    }


def primary_title(context: dict[str, Any]) -> str:
    title = str(context.get("case_title") or "case activity")
    if "backlog" in title.lower():
        return f"Telemetry backlog requiring triage: {title}"[:140]
    if context.get("observed_technique_chain"):
        return f"Evidence-grounded security hypothesis for {title}"[:140]
    return f"Low-context hypothesis for {title}"[:140]


def clean_primary_description(context: dict[str, Any]) -> str:
    tactics = sorted(
        {
            str(mapping.get("tactic"))
            for mapping in context.get("mitre_tactic_mappings") or []
            if mapping.get("tactic") and mapping.get("tactic") != "unknown"
        }
    )
    safe = str(context.get("safe_conclusion") or "").strip()
    observed = ", ".join(tactics[:5]) if tactics else "the observed case activity"
    if safe.lower().startswith("the evidence supports "):
        return f"The supplied evidence supports {observed}. {safe}"
    return f"The supplied evidence supports {observed}. {safe}".strip()


def normalize_checks(checks: list[str]) -> list[str]:
    defaults = [
        "review authentication timeline",
        "review network connections",
        "review EDR/Sysmon if available",
        "escalate to Tier 2 for validation",
    ]
    result: list[str] = []
    for check in checks + defaults:
        text = str(check).strip()
        if text and text not in result:
            result.append(text)
    return result


def extract_output_text(response: dict[str, Any]) -> str:
    if response.get("output_text"):
        return str(response["output_text"])
    for item in response.get("output") or []:
        for content in item.get("content") or []:
            if content.get("type") in {"output_text", "text"} and content.get("text"):
                return str(content["text"])
    raise RuntimeError("Provider response did not contain output text.")


def parse_json_response_text(text: str) -> dict[str, Any]:
    stripped = text.strip()
    if not stripped:
        raise ValueError("empty output text")
    try:
        parsed = json.loads(stripped)
        if isinstance(parsed, dict):
            return parsed
        raise ValueError("top-level JSON value is not an object")
    except json.JSONDecodeError:
        decoder = json.JSONDecoder()
        parsed, _index = decoder.raw_decode(stripped)
        if isinstance(parsed, dict):
            return parsed
        raise ValueError("raw-decoded JSON value is not an object")


def openai_hypothesis_schema() -> dict[str, Any]:
    return {
        "type": "object",
        "additionalProperties": False,
        "required": ["case_id", "provider", "generated_at_utc", "hypotheses"],
        "properties": {
            "case_id": {"type": "string"},
            "provider": {"type": "string"},
            "generated_at_utc": {"type": "string"},
            "hypotheses": {
                "type": "array",
                "minItems": 2,
                "maxItems": 4,
                "items": {
                    "type": "object",
                    "additionalProperties": False,
                    "required": [
                        "hypothesis_id",
                        "title",
                        "description",
                        "claim_type",
                        "confidence_score",
                        "confidence_label",
                        "supporting_evidence_ids",
                        "supporting_alert_uids",
                        "mitre_techniques",
                        "mitre_tactic_mappings",
                        "observed_facts",
                        "inferred_facts",
                        "missing_evidence",
                        "recommended_checks",
                        "forbidden_claims_respected",
                        "limitations",
                    ],
                    "properties": {
                        "hypothesis_id": {"type": "string"},
                        "title": {"type": "string"},
                        "description": {"type": "string"},
                        "claim_type": {"type": "string", "enum": ["evidence_grounded", "investigative_gap", "alternative_explanation"]},
                        "confidence_score": {"type": "number"},
                        "confidence_label": {"type": "string", "enum": ["high", "medium", "low", "weak"]},
                        "supporting_evidence_ids": {"type": "array", "items": {"type": "string"}},
                        "supporting_alert_uids": {"type": "array", "items": {"type": "string"}},
                        "mitre_techniques": {"type": "array", "items": {"type": "string"}},
                        "mitre_tactic_mappings": {
                            "type": "array",
                            "items": {
                                "type": "object",
                                "additionalProperties": False,
                                "required": ["technique_id", "tactic", "technique_name"],
                                "properties": {
                                    "technique_id": {"type": "string"},
                                    "tactic": {"type": "string"},
                                    "technique_name": {"type": "string"},
                                },
                            },
                        },
                        "observed_facts": {"type": "array", "items": {"type": "string"}},
                        "inferred_facts": {"type": "array", "items": {"type": "string"}},
                        "missing_evidence": {
                            "type": "array",
                            "items": {
                                "type": "object",
                                "additionalProperties": False,
                                "required": ["missing_evidence_type", "status", "reason"],
                                "properties": {
                                    "missing_evidence_type": {"type": "string"},
                                    "status": {"type": "string"},
                                    "reason": {"type": "string"},
                                },
                            },
                        },
                        "recommended_checks": {"type": "array", "items": {"type": "string"}},
                        "forbidden_claims_respected": {"type": "boolean"},
                        "limitations": {"type": "array", "items": {"type": "string"}},
                    },
                },
            },
        },
    }
