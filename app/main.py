from __future__ import annotations

from pathlib import Path

from fastapi import FastAPI, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.middleware.sessions import SessionMiddleware

from .auth import clear_authentication, is_authenticated, mark_authenticated
from .config import load_llm_settings, load_prompt_file, load_settings
from .job_store import JobStore
from .llm_client import LLMClientError, generate_report_sections
from .models import JobRecord, ScanMode, ScanRequest
from .nmap_parser import parse_nmap_output
from .report_profiles import DETAILED_PROFILE, get_profile_sections, get_report_profile
from .report_builder import build_fallback_report_sections
from .scan_runner import get_operation_specs, run_scan

settings = load_settings()
llm_settings = load_llm_settings(settings.llm_config_path)
prompt_map = {
    DETAILED_PROFILE: load_prompt_file(llm_settings.detailed_report_prompt_file),
    "operation_summary": load_prompt_file(llm_settings.summary_prompt_file),
}
app = FastAPI(title=settings.app_name)
app.add_middleware(
    SessionMiddleware,
    secret_key=settings.session_secret,
    same_site="lax",
    https_only=False,
)

base_dir = Path(__file__).resolve().parent
templates = Jinja2Templates(directory=str(base_dir / "templates"))
app.mount("/static", StaticFiles(directory=str(base_dir / "static")), name="static")
store = JobStore(settings.data_dir)


def redirect(path: str) -> RedirectResponse:
    return RedirectResponse(url=path, status_code=303)


def require_auth(request: Request) -> None:
    if not is_authenticated(request):
        raise HTTPException(status_code=303, headers={"Location": "/unlock"})


@app.get("/", response_class=HTMLResponse)
def index(request: Request) -> HTMLResponse:
    if not is_authenticated(request):
        return redirect("/unlock")

    jobs = store.list_jobs()
    return templates.TemplateResponse(
        request,
        "dashboard.html",
        {
            "app_name": settings.app_name,
            "jobs": jobs,
            "operation_specs": get_operation_specs(),
            "llm_settings": llm_settings,
        },
    )


@app.get("/unlock", response_class=HTMLResponse)
def unlock_page(request: Request) -> HTMLResponse:
    return templates.TemplateResponse(
        request,
        "unlock.html",
        {"app_name": settings.app_name, "error": None},
    )


@app.post("/unlock", response_class=HTMLResponse)
def unlock_submit(request: Request, password: str = Form(...)) -> HTMLResponse:
    if password != settings.admin_password:
        return templates.TemplateResponse(
            request,
            "unlock.html",
            {"app_name": settings.app_name, "error": "Invalid password."},
            status_code=401,
        )

    mark_authenticated(request)
    return redirect("/")


@app.post("/logout")
def logout(request: Request) -> RedirectResponse:
    clear_authentication(request)
    return redirect("/unlock")


@app.post("/scan")
def create_scan(
    request: Request,
    target: str = Form(...),
    mode: ScanMode = Form(...),
    interface: str = Form(""),
    packet_count: int = Form(100),
) -> RedirectResponse:
    require_auth(request)

    scan_request = ScanRequest(
        target=target,
        mode=mode,
        interface=interface or None,
        packet_count=packet_count,
    )
    job = JobRecord.build(job_id=store.create_id(), request=scan_request)
    store.create(job)
    job.result = run_scan(scan_request)
    parsed_scan = (
        parse_nmap_output(job.result.stdout)
        if job.result and job.result.command and job.result.command[0] == "nmap"
        else {}
    )
    report_profile = get_report_profile(job.request.mode)
    try:
        sections, metadata = generate_report_sections(
            llm_settings=llm_settings,
            system_prompt=prompt_map[report_profile],
            job=job,
            parsed_scan=parsed_scan,
            report_profile=report_profile,
        )
    except LLMClientError as exc:
        sections, metadata = build_fallback_report_sections(
            job=job,
            parsed_scan=parsed_scan,
            llm_error=str(exc),
        )
    job.report_sections = sections
    job.report_metadata = metadata | {
        "parsed_scan": parsed_scan,
        "section_order": list(get_profile_sections(report_profile)),
    }
    store.save(job)
    return redirect(f"/jobs/{job.job_id}")


@app.get("/jobs/{job_id}", response_class=HTMLResponse)
def job_detail(request: Request, job_id: str) -> HTMLResponse:
    require_auth(request)
    job = store.load(job_id)
    if job is None:
        raise HTTPException(status_code=404, detail="Job not found.")
    return templates.TemplateResponse(
        request,
        "job_detail.html",
        {"app_name": settings.app_name, "job": job},
    )
