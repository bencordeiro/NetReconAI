from __future__ import annotations

from fastapi import Request

SESSION_KEY = "authenticated"


def is_authenticated(request: Request) -> bool:
    return bool(request.session.get(SESSION_KEY))


def mark_authenticated(request: Request) -> None:
    request.session[SESSION_KEY] = True


def clear_authentication(request: Request) -> None:
    request.session.clear()
