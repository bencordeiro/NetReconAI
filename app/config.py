from __future__ import annotations

import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from dotenv import load_dotenv


@dataclass(frozen=True)
class Settings:
    admin_password: str
    session_secret: str
    data_dir: Path
    llm_config_path: Path
    app_name: str = "NetReconAI"


@dataclass(frozen=True)
class LLMSettings:
    provider: str
    base_url: str
    model: str
    api_key_env: str
    timeout_seconds: int
    temperature: float
    max_tokens: int
    detailed_report_prompt_file: Path
    summary_prompt_file: Path
    allow_model_html_sections: bool


def load_settings() -> Settings:
    root_dir = Path(__file__).resolve().parent.parent
    load_dotenv(root_dir / ".env")
    data_dir_value = os.getenv("NETRECON_DATA_DIR", "data")
    data_dir = Path(data_dir_value)
    if not data_dir.is_absolute():
        data_dir = root_dir / data_dir

    llm_config_value = os.getenv("NETRECON_LLM_CONFIG", "config/llm_config.json")
    llm_config_path = Path(llm_config_value)
    if not llm_config_path.is_absolute():
        llm_config_path = root_dir / llm_config_path

    return Settings(
        admin_password=os.getenv("NETRECON_ADMIN_PASSWORD", "change-me"),
        session_secret=os.getenv(
            "NETRECON_SESSION_SECRET", "replace-with-a-long-random-string"
        ),
        data_dir=data_dir,
        llm_config_path=llm_config_path,
    )


def load_llm_settings(config_path: Path) -> LLMSettings:
    config_data: dict[str, Any] = json.loads(config_path.read_text(encoding="utf-8"))
    root_dir = Path(__file__).resolve().parent.parent

    detailed_prompt_value = config_data.get(
        "detailed_report_prompt_file", config_data.get("report_prompt_file")
    )
    summary_prompt_value = config_data.get(
        "summary_prompt_file", "config/prompts/summary_system_prompt.txt"
    )

    detailed_report_prompt_file = Path(detailed_prompt_value)
    if not detailed_report_prompt_file.is_absolute():
        detailed_report_prompt_file = root_dir / detailed_report_prompt_file

    summary_prompt_file = Path(summary_prompt_value)
    if not summary_prompt_file.is_absolute():
        summary_prompt_file = root_dir / summary_prompt_file

    request_config = config_data.get("request", {})
    html_policy = config_data.get("html_policy", {})

    return LLMSettings(
        provider=str(config_data["provider"]),
        base_url=str(config_data["base_url"]),
        model=str(config_data["model"]),
        api_key_env=str(config_data.get("api_key_env", "OPENAI_API_KEY")),
        timeout_seconds=int(config_data.get("timeout_seconds", 120)),
        temperature=float(request_config.get("temperature", 0.2)),
        max_tokens=int(request_config.get("max_tokens", 1800)),
        detailed_report_prompt_file=detailed_report_prompt_file,
        summary_prompt_file=summary_prompt_file,
        allow_model_html_sections=bool(
            html_policy.get("allow_model_html_sections", False)
        ),
    )


def load_prompt_file(path: Path) -> str:
    return path.read_text(encoding="utf-8").strip()
