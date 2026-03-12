from __future__ import annotations

import re


HOST_REPORT_RE = re.compile(r"^Nmap scan report for (?P<host>.+)$", re.MULTILINE)
DONE_RE = re.compile(
    r"Nmap done:\s+(?P<ip_count>\d+)\s+IP addresses\s+\((?P<hosts_up>\d+)\s+hosts up\)",
    re.IGNORECASE,
)
PORT_LINE_RE = re.compile(
    r"^(?P<port>\d+/\w+)\s+(?P<state>\S+)\s+(?P<service>\S+)(?:\s+(?P<version>.+))?$"
)


def parse_nmap_output(stdout: str) -> dict[str, object]:
    live_hosts = [match.group("host") for match in HOST_REPORT_RE.finditer(stdout)]
    totals_match = DONE_RE.search(stdout)

    open_ports: list[dict[str, str]] = []
    current_host: str | None = None
    for line in stdout.splitlines():
        host_match = HOST_REPORT_RE.match(line)
        if host_match:
            current_host = host_match.group("host")
            continue

        port_match = PORT_LINE_RE.match(line.strip())
        if current_host and port_match:
            state = port_match.group("state")
            if state == "open":
                open_ports.append(
                    {
                        "host": current_host,
                        "port": port_match.group("port"),
                        "service": port_match.group("service"),
                        "version": (port_match.group("version") or "").strip(),
                    }
                )

    summary: dict[str, object] = {
        "live_hosts": live_hosts,
        "live_host_count": len(live_hosts),
        "open_ports": open_ports,
        "open_port_count": len(open_ports),
    }

    if totals_match:
        summary["scanned_ip_count"] = int(totals_match.group("ip_count"))
        summary["hosts_up"] = int(totals_match.group("hosts_up"))

    return summary
