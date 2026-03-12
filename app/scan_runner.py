from __future__ import annotations

import shutil
import subprocess
import time
from dataclasses import dataclass
from datetime import datetime, timezone

from .models import ScanMode, ScanRequest, ScanResult


@dataclass(frozen=True)
class OperationSpec:
    mode: ScanMode
    label: str
    description: str
    tool: str
    root_note: str | None = None


OPERATION_SPECS: tuple[OperationSpec, ...] = (
    OperationSpec(
        mode=ScanMode.host_discovery,
        label="Host Discovery",
        description="Identify reachable hosts in a subnet or target range using nmap host discovery.",
        tool="nmap",
    ),
    OperationSpec(
        mode=ScanMode.deep_scan,
        label="Deep Scan On Endpoint",
        description="Enumerate common ports, services, default scripts, and OS fingerprinting on a selected endpoint.",
        tool="nmap",
        root_note="Uses Nmap OS fingerprinting and typically requires sudo.",
    ),
    OperationSpec(
        mode=ScanMode.vuln_scan,
        label="Vulnerability Script Scan",
        description="Run Nmap NSE vulnerability checks against detected services using the vuln script set.",
        tool="nmap",
    ),
    OperationSpec(
        mode=ScanMode.ping_probe,
        label="Ping Probe",
        description="Send a short ICMP probe to verify reachability and latency for a specific target.",
        tool="ping",
    ),
    OperationSpec(
        mode=ScanMode.tshark_capture,
        label="Tshark Capture",
        description="Capture and decode a limited packet sample for the specified host.",
        tool="tshark",
        root_note="Usually requires sudo or capture capabilities.",
    ),
    OperationSpec(
        mode=ScanMode.nslookup_query,
        label="NSLookup Query",
        description="Resolve DNS records for a host or domain using nslookup.",
        tool="nslookup",
    ),
    OperationSpec(
        mode=ScanMode.dig_query,
        label="Dig Query",
        description="Run a compact DNS lookup with dig for a host or domain.",
        tool="dig",
    ),
    OperationSpec(
        mode=ScanMode.whois_query,
        label="WHOIS Query",
        description="Retrieve registrar or ownership context for a domain or IP target.",
        tool="whois",
    ),
    OperationSpec(
        mode=ScanMode.traceroute_path,
        label="Traceroute Path",
        description="Trace the network path toward a host to inspect routing hops and latency.",
        tool="traceroute",
        root_note="May require sudo depending on traceroute method and host configuration.",
    ),
    OperationSpec(
        mode=ScanMode.arp_scan,
        label="ARP Scan",
        description="Identify local-network devices on the current segment with ARP scanning.",
        tool="arp-scan",
        root_note="Typically requires sudo on the local segment.",
    ),
    OperationSpec(
        mode=ScanMode.curl_inspect,
        label="HTTP Inspect",
        description="Fetch HTTP headers and page content for later manual review or AI summarization.",
        tool="curl",
    ),
)


def get_operation_specs() -> list[dict[str, str]]:
    specs: list[dict[str, str]] = []
    for spec in OPERATION_SPECS:
        specs.append(
            {
                "value": spec.mode.value,
                "label": spec.label,
                "description": spec.description,
                "tool": spec.tool,
                "root_note": spec.root_note or "",
            }
        )
    return specs


def _normalize_http_target(target: str) -> str:
    if target.startswith("http://") or target.startswith("https://"):
        return target
    return f"http://{target}"


def build_command(scan: ScanRequest) -> list[str]:
    interface = scan.interface or "any"

    if scan.mode == ScanMode.host_discovery:
        return ["nmap", "-sn", scan.target]
    if scan.mode == ScanMode.deep_scan:
        return ["nmap", "-sV", "-sC", "-O", "-Pn", scan.target]
    if scan.mode == ScanMode.vuln_scan:
        return ["nmap", "-sV", "--script", "vuln", "-Pn", scan.target]
    if scan.mode == ScanMode.ping_probe:
        return ["ping", "-c", "4", scan.target]
    if scan.mode == ScanMode.tshark_capture:
        return ["tshark", "-i", interface, "-f", f"host {scan.target}", "-c", str(scan.packet_count)]
    if scan.mode == ScanMode.nslookup_query:
        return ["nslookup", scan.target]
    if scan.mode == ScanMode.traceroute_path:
        return ["traceroute", scan.target]
    if scan.mode == ScanMode.dig_query:
        return ["dig", "+noall", "+answer", "+comments", scan.target]
    if scan.mode == ScanMode.whois_query:
        return ["whois", scan.target]
    if scan.mode == ScanMode.arp_scan:
        return ["arp-scan", "--localnet"]
    if scan.mode == ScanMode.curl_inspect:
        return [
            "curl",
            "-k",
            "-L",
            "-sS",
            "-D",
            "-",
            "--max-time",
            "20",
            "--max-filesize",
            "200000",
            _normalize_http_target(scan.target),
        ]
    raise ValueError(f"Unsupported scan mode: {scan.mode}")


def run_scan(scan: ScanRequest) -> ScanResult:
    command = build_command(scan)
    started = datetime.now(timezone.utc).isoformat()
    start_monotonic = time.monotonic()

    if shutil.which(command[0]) is None:
        finished = datetime.now(timezone.utc).isoformat()
        return ScanResult(
            command=command,
            stdout="",
            stderr=f"Required tool `{command[0]}` was not found on the host.",
            exit_code=127,
            started_at=started,
            finished_at=finished,
            duration_seconds=time.monotonic() - start_monotonic,
            status="missing_tool",
        )

    try:
        completed = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=900,
            check=False,
        )
        finished = datetime.now(timezone.utc).isoformat()
    except subprocess.TimeoutExpired as exc:
        finished = datetime.now(timezone.utc).isoformat()
        return ScanResult(
            command=command,
            stdout=exc.stdout or "",
            stderr=(exc.stderr or "") + "\nCommand timed out before completion.",
            exit_code=124,
            started_at=started,
            finished_at=finished,
            duration_seconds=time.monotonic() - start_monotonic,
            status="timeout",
        )

    return ScanResult(
        command=command,
        stdout=completed.stdout,
        stderr=completed.stderr,
        exit_code=completed.returncode,
        started_at=started,
        finished_at=finished,
        duration_seconds=time.monotonic() - start_monotonic,
        status="completed" if completed.returncode == 0 else "failed",
    )
