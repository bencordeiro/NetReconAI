from __future__ import annotations

import json
from pathlib import Path
from uuid import uuid4

from .models import JobRecord, ScanResult


class JobStore:
    def __init__(self, data_dir: Path) -> None:
        self.base_dir = data_dir / "jobs"
        self.base_dir.mkdir(parents=True, exist_ok=True)

    def _job_dir(self, job_id: str) -> Path:
        return self.base_dir / job_id

    def create(self, record: JobRecord) -> JobRecord:
        job_dir = self._job_dir(record.job_id)
        job_dir.mkdir(parents=True, exist_ok=True)
        self.save(record)
        return record

    def create_id(self) -> str:
        return uuid4().hex[:12]

    def save(self, record: JobRecord) -> None:
        job_dir = self._job_dir(record.job_id)
        job_dir.mkdir(parents=True, exist_ok=True)
        (job_dir / "request.json").write_text(
            json.dumps(record.model_dump(mode="json"), indent=2), encoding="utf-8"
        )
        if record.result is not None:
            (job_dir / "stdout.txt").write_text(record.result.stdout, encoding="utf-8")
            (job_dir / "stderr.txt").write_text(record.result.stderr, encoding="utf-8")

    def list_jobs(self) -> list[JobRecord]:
        records: list[JobRecord] = []
        for path in sorted(self.base_dir.glob("*/request.json"), reverse=True):
            data = json.loads(path.read_text(encoding="utf-8"))
            records.append(JobRecord.model_validate(data))
        return records

    def load(self, job_id: str) -> JobRecord | None:
        request_file = self._job_dir(job_id) / "request.json"
        if not request_file.exists():
            return None
        data = json.loads(request_file.read_text(encoding="utf-8"))
        return JobRecord.model_validate(data)
