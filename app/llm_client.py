from __future__ import annotations

import json
import os
from typing import Any
from urllib import error, request

from .config import LLMSettings
from .models import JobRecord
from .report_profiles import DETAILED_PROFILE, get_profile_sections


class LLMClientError(Exception):
    pass


def _normalize_section_value(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, str):
        return value.strip()
    if isinstance(value, (int, float, bool)):
        return str(value)
    if isinstance(value, list):
        lines: list[str] = []
        for item in value:
            normalized = _normalize_section_value(item)
            if normalized:
                lines.append(f"- {normalized}")
        return "\n".join(lines).strip()
    if isinstance(value, dict):
        preferred_keys = [
            "description",
            "summary",
            "title",
            "observation",
            "rationale",
            "context",
            "evidence",
            "details",
            "limitations",
            "recommendation",
        ]
        ordered_values: list[str] = []
        used_keys: set[str] = set()
        for key in preferred_keys:
            if key in value:
                normalized = _normalize_section_value(value[key])
                if normalized:
                    ordered_values.append(normalized)
                used_keys.add(key)

        for key, item in value.items():
            if key in used_keys:
                continue
            normalized = _normalize_section_value(item)
            if normalized:
                label = key.replace("_", " ").capitalize()
                if isinstance(item, (dict, list)):
                    ordered_values.append(f"{label}:\n{normalized}")
                else:
                    ordered_values.append(f"{label}: {normalized}")

        return "\n".join(ordered_values).strip()

    return str(value).strip()


def _extract_json_object(text: str) -> dict[str, Any]:
    stripped = text.strip()
    if stripped.startswith("```"):
        lines = stripped.splitlines()
        if len(lines) >= 3:
            stripped = "\n".join(lines[1:-1]).strip()

    start = stripped.find("{")
    end = stripped.rfind("}")
    if start == -1 or end == -1 or end <= start:
        raise LLMClientError("Model response did not contain a JSON object.")

    try:
        return json.loads(stripped[start : end + 1])
    except json.JSONDecodeError as exc:
        raise LLMClientError(f"Model returned invalid JSON: {exc}") from exc


def _build_messages(
    system_prompt: str,
    job: JobRecord,
    parsed_scan: dict[str, Any],
    report_profile: str,
) -> list[dict[str, str]]:
    result = job.result
    if result is None:
        raise LLMClientError("No scan result is available for report generation.")

    truncated_stdout = result.stdout[:12000]
    truncated_stderr = result.stderr[:4000]
    user_payload = {
        "job_id": job.job_id,
        "created_at": job.created_at,
        "scan_mode": job.request.mode.value,
        "target": job.request.target,
        "command": result.command,
        "status": result.status,
        "exit_code": result.exit_code,
        "duration_seconds": result.duration_seconds,
        "parsed_scan": parsed_scan,
        "stdout_excerpt": truncated_stdout,
        "stderr_excerpt": truncated_stderr,
    }

    section_keys = [key for key, _ in get_profile_sections(report_profile)]
    profile_instruction = (
        "This is a full assessment-style operation. Maintain a security-report tone and use the complete report outline."
        if report_profile == DETAILED_PROFILE
        else "This is a lightweight operational check. Keep the output concise and do not force a vulnerability-report tone."
    )
    user_prompt = (
        "Produce a strict JSON object with exactly these keys: "
        f"{', '.join(section_keys)}. "
        "Base the content only on the supplied scan data. "
        "Prefer plain paragraph strings for each value. If needed, short arrays or objects are acceptable. "
        "Do not wrap the JSON in markdown fences. "
        f"{profile_instruction}\n\n"
        f"Scan payload:\n{json.dumps(user_payload, indent=2)}"
    )

    return [
        {"role": "system", "content": system_prompt},
        {"role": "user", "content": user_prompt},
    ]


def generate_report_sections(
    llm_settings: LLMSettings,
    system_prompt: str,
    job: JobRecord,
    parsed_scan: dict[str, Any],
    report_profile: str,
) -> tuple[dict[str, str], dict[str, Any]]:
    body = {
        "model": llm_settings.model,
        "messages": _build_messages(system_prompt, job, parsed_scan, report_profile),
        "temperature": llm_settings.temperature,
        "max_tokens": llm_settings.max_tokens,
    }

    payload = json.dumps(body).encode("utf-8")
    endpoint = llm_settings.base_url.rstrip("/") + "/chat/completions"
    headers = {"Content-Type": "application/json"}

    if llm_settings.api_key_env:
        api_key = os.getenv(llm_settings.api_key_env, "")
        if api_key:
            headers["Authorization"] = f"Bearer {api_key}"

    req = request.Request(endpoint, data=payload, headers=headers, method="POST")
    try:
        with request.urlopen(req, timeout=llm_settings.timeout_seconds) as response:
            response_data = json.loads(response.read().decode("utf-8"))
    except error.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")
        raise LLMClientError(f"LLM API HTTP {exc.code}: {detail}") from exc
    except error.URLError as exc:
        raise LLMClientError(f"LLM API connection failed: {exc.reason}") from exc

    try:
        content = response_data["choices"][0]["message"]["content"]
    except (KeyError, IndexError, TypeError) as exc:
        raise LLMClientError("LLM API response did not contain chat completion content.") from exc

    parsed = _extract_json_object(content)
    sections: dict[str, str] = {}
    for section_key, _ in get_profile_sections(report_profile):
        sections[section_key] = _normalize_section_value(parsed.get(section_key, ""))
    metadata = {
        "source": "llm",
        "provider": llm_settings.provider,
        "base_url": llm_settings.base_url,
        "model": llm_settings.model,
        "profile": report_profile,
    }
    return sections, metadata
