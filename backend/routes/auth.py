import math
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.orm import Session

import config
from deps import get_db
from schemas import LoginRequest
from security import require_admin
from services import auth, ledger

router = APIRouter(prefix="/auth", tags=["Authentication"])


def client_ip(request: Request) -> str:
    return request.client.host if request.client else "unknown"


def _user(claims: dict) -> dict:
    return {
        "username": claims["sub"],
        "role": claims["role"],
        "demo_mode": config.DEMO_MODE,
        "expires_at": datetime.fromtimestamp(claims["exp"], timezone.utc).isoformat(),
    }


@router.post("/login")
def login(body: LoginRequest, request: Request, db: Session = Depends(get_db)):
    ip = client_ip(request)

    wait = auth.login_limiter.retry_after(ip)
    if wait:
        raise HTTPException(
            status_code=429,
            detail=f"Too many failed attempts. Try again in {math.ceil(wait / 60)} minute(s).",
            headers={"Retry-After": str(wait)},
        )

    if not auth.check_admin_credentials(body.username, body.password):
        auth.login_limiter.record_failure(ip)
        ledger.record_server_event(db, "DASHBOARD_LOGIN_FAILED", body.username, ip,
                                   f"Failed dashboard login for user '{body.username[:100]}'")
        raise HTTPException(status_code=401, detail="Invalid username or password")

    auth.login_limiter.reset(ip)
    token, _ = auth.issue_token(body.username)
    claims = auth.verify_token(token)
    ledger.record_server_event(db, "DASHBOARD_LOGIN_SUCCESS", body.username, ip,
                               f"User '{body.username}' logged in to the dashboard")
    return {"access_token": token, "token_type": "bearer", "user": _user(claims)}


@router.get("/me")
def me(claims: dict = Depends(require_admin)):
    return _user(claims)


@router.post("/logout")
def logout(request: Request, claims: dict = Depends(require_admin), db: Session = Depends(get_db)):
    auth.revoke_token(claims)
    ledger.record_server_event(db, "DASHBOARD_LOGOUT", claims["sub"], client_ip(request),
                               f"User '{claims['sub']}' logged out")
    return {"status": "Logged out"}