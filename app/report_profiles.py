from __future__ import annotations

from .models import ScanMode

DETAILED_PROFILE = "detailed_report"
SUMMARY_PROFILE = "operation_summary"

DETAILED_SECTIONS: tuple[tuple[str, str], ...] = (
    ("executive_summary", "Executive Summary"),
    ("key_findings", "Key Findings"),
    ("security_posture", "Security Posture"),
    ("recommended_actions", "Recommended Actions"),
    ("evidence_caveats", "Evidence Caveats"),
)

SUMMARY_SECTIONS: tuple[tuple[str, str], ...] = (
    ("summary", "Summary"),
    ("key_observations", "Key Observations"),
    ("suggested_follow_up", "Suggested Follow-Up"),
    ("evidence_caveats", "Evidence Caveats"),
)


def get_report_profile(mode: ScanMode) -> str:
    if mode in {
        ScanMode.host_discovery,
        ScanMode.deep_scan,
        ScanMode.vuln_scan,
        ScanMode.tshark_capture,
        ScanMode.arp_scan,
        ScanMode.curl_inspect,
    }:
        return DETAILED_PROFILE
    return SUMMARY_PROFILE


def get_profile_sections(profile: str) -> tuple[tuple[str, str], ...]:
    if profile == DETAILED_PROFILE:
        return DETAILED_SECTIONS
    return SUMMARY_SECTIONS
