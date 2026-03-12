## Main App Entry

- `app/main.py`
  - FastAPI application setup
  - session middleware
  - password gate routes
  - dashboard route
  - scan creation route
  - job detail route

## Core App Logic

- `app/config.py`
  - loads base app settings
  - loads external LLM config
  - loads the detailed and summary system prompts

- `app/auth.py`
  - shared admin password session helpers

- `app/models.py`
  - request and job models
  - scan mode definitions

- `app/scan_runner.py`
  - predefined `nmap` scan actions
  - predefined DNS, routing, host-discovery, capture, and HTTP inspection actions
  - safe command building
  - subprocess execution and stdout/stderr capture

- `app/job_store.py`
  - file-based job persistence
  - writes JSON metadata and raw output files

- `app/report_builder.py`
  - backend-generated report section placeholders
  - current non-LLM summary logic

## UI Files

- `app/templates/base.html`
  - shared layout shell

- `app/templates/unlock.html`
  - shared password entry page

- `app/templates/dashboard.html`
  - scan launcher
  - job history
  - current visible LLM endpoint/model info

- `app/templates/job_detail.html`
  - report view
  - raw stdout/stderr view

- `app/static/styles.css`
  - desktop-first styling

## Config Files

- `.env.example`
  - app environment variables
  - admin password
  - session secret
  - data directory
  - path to the LLM config file
  - optional API key example for endpoints that require auth

- `config/llm_config.json`
  - OpenAI-compatible LLM endpoint settings
  - model name
  - optional API key env binding
  - timeout
  - request parameters
  - detailed and summary prompt file locations

- `config/prompts/detailed_report_system_prompt.txt`
  - editable system prompt for full assessment-style reports

- `config/prompts/summary_system_prompt.txt`
  - editable system prompt for lightweight operational summaries

## Planning Docs

- `PROJECT_OUTLINE.md`
  - product direction
  - architecture
  - scope
  - phased build plan

- `PROJECT_NAVIGATION.md`
  - this file

## Runtime Data

- `data/jobs/<job-id>/request.json`
  - saved job metadata

- `data/jobs/<job-id>/stdout.txt`
  - raw tool stdout

- `data/jobs/<job-id>/stderr.txt`
  - raw tool stderr

These are created after scans run.

## Best Next Build Targets

If you continue development, the highest-value next files to add are:

- `app/llm_client.py`
  - OpenAI-compatible API client for `vLLM` or similar

- `app/nmap_parser.py`
  - structured extraction of hosts, ports, services, and versions

- `app/report_templates/`
  - richer backend-controlled report sections and export layouts

- `app/pdf.py`
  - HTML-to-PDF rendering path
