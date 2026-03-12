from __future__ import annotations

from .models import JobRecord, ScanMode
from .report_profiles import DETAILED_PROFILE, SUMMARY_PROFILE, get_report_profile


def build_fallback_report_sections(
    job: JobRecord,
    parsed_scan: dict[str, object] | None = None,
    llm_error: str | None = None,
) -> tuple[dict[str, str], dict[str, str]]:
    result = job.result
    if result is None:
        return {}, {"source": "none"}

    mode_summaries = {
        ScanMode.host_discovery: "Host discovery run intended to identify reachable systems without deeper service enumeration.",
        ScanMode.deep_scan: "Deeper scan intended to enumerate open ports, service banners, and default NSE script output for a specific endpoint.",
        ScanMode.vuln_scan: "Nmap vulnerability script run intended to identify known weak points based on detected service versions and NSE checks.",
        ScanMode.ping_probe: "Basic reachability probe intended to confirm whether the target responds to ICMP echo requests.",
        ScanMode.tshark_capture: "Packet capture and decode run intended to inspect a bounded traffic sample involving the selected host.",
        ScanMode.nslookup_query: "DNS lookup run intended to resolve records associated with a host or domain.",
        ScanMode.traceroute_path: "Path trace run intended to show network hops and latency on the route to the target.",
        ScanMode.dig_query: "DNS query run intended to return compact resolver output for the selected host or domain.",
        ScanMode.whois_query: "WHOIS lookup intended to provide ownership, registrar, and registration context for a domain or IP range.",
        ScanMode.arp_scan: "ARP scan intended to identify live systems on the local network segment.",
        ScanMode.curl_inspect: "HTTP inspection run intended to retrieve headers and page content for quick review and later AI summarization.",
    }
    summary = mode_summaries[job.request.mode]
    profile = get_report_profile(job.request.mode)
    live_count = None if not parsed_scan else parsed_scan.get("live_host_count")
    open_port_count = None if not parsed_scan else parsed_scan.get("open_port_count")

    if result.exit_code != 0:
        risk_note = "The scan did not complete cleanly. Review stderr before relying on conclusions."
    elif "open" in result.stdout.lower():
        risk_note = "Open services were detected. Review exposed ports and service versions carefully."
    else:
        risk_note = "No obvious open-service indicators were found in the raw output, but this is not a security guarantee."

    key_findings = (
        f"Live hosts detected: {live_count}." if isinstance(live_count, int) else "Review raw output for discovered hosts."
    )
    if isinstance(open_port_count, int) and open_port_count > 0:
        key_findings += f" Open ports detected: {open_port_count}."

    tool_observation = (
        f"Command completed with status `{result.status}` in "
        f"{result.duration_seconds:.2f} seconds."
    )
    if profile == DETAILED_PROFILE:
        sections = {
            "executive_summary": summary,
            "key_findings": key_findings,
            "security_posture": risk_note,
            "tool_observation": tool_observation,
            "recommended_actions": (
                "Inspect responsive hosts first, then run deeper scans on selected endpoints to enumerate services."
            ),
            "evidence_caveats": (
                llm_error
                if llm_error
                else "This report was generated without LLM assistance. Validate notable findings manually."
            ),
        }
    else:
        sections = {
            "summary": summary,
            "key_observations": f"{key_findings} {tool_observation}".strip(),
            "suggested_follow_up": "Run a deeper scan only if you need service, vulnerability, or traffic detail.",
            "evidence_caveats": (
                llm_error
                if llm_error
                else "This was a lightweight operational summary, not a full security assessment."
            ),
        }
    metadata = {"source": "fallback", "profile": profile}
    if llm_error:
        metadata["llm_error"] = llm_error
    return sections, metadata
