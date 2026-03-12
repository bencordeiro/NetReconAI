# NetReconAI

FastAPI-based network recon dashboard with predefined, safe scan actions, job history, and LLM-assisted reporting. Designed to be a powerful network admin and analyst tool. Easily read summarized network traffic with your choice of LLM.

## Features

- Shared admin password.
- Safe command building for Nmap and common network tools.
- Optional LLM report configuration via `config/llm_config.json`.

## Requirements

- Python 3.11+
- System tools as needed by each action:
  - `nmap`, `tshark`, `arp-scan`, `whois`, `dig`, `nslookup`, `traceroute`, `curl`, `ping`

## Quickstart

1. Create a virtual environment.
2. Install `requirements.txt`.
3. Copy `.env.example` to `.env` and edit values.
4. Edit `config/llm_config.json` and prompt files in `config/prompts/`.
5. Start the app:

```bash
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

The app loads `.env` from the project root automatically.

## Configure The LLM

Update `config/llm_config.json`:

- `base_url`: OpenAI-compatible endpoint URL.
- `model`: Model name served by your endpoint.
- `api_key_env`: Environment variable name that holds your API key, or leave empty for keyless endpoints.

Optional: set `OPENAI_API_KEY` in `.env` if your endpoint requires it.

## Available Actions

- Host Discovery (`nmap -sn`)
- Deep Scan On Endpoint (`nmap -sV -sC -O -Pn`)
- Vulnerability Script Scan (`nmap --script vuln`)
- Ping Probe
- Tshark Capture
- NSLookup Query
- Dig Query
- WHOIS Query
- Traceroute Path
- ARP Scan (local segment)
- HTTP Inspect (curl)

## Data

Runtime scan artifacts are stored under `data/jobs/<job-id>/`. These contain targets, command output, and report content. Do not commit this directory to a public repo. The included `.gitignore` already excludes `data/jobs/` and `.env`.

## Notes

- Some actions require elevated privileges (for example `nmap -O`, `tshark`, `arp-scan`).

## Images & Demo
<img width="1559" height="1239" alt="photo2" src="https://github.com/user-attachments/assets/320e6126-bf74-417e-b801-007e769c51c9" />
<img width="1549" height="1135" alt="photo1" src="https://github.com/user-attachments/assets/311bf021-0a06-42b9-94e3-f44436469e12" />

