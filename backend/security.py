"""
FastAPI dependencies that protect the endpoints.

  require_agent  -> log agents (X-API-KEY header). Returns the agent's name.
  require_admin  -> dashboard users (Authorization: Bearer <token>). Returns claims.
  require_demo   -> demo attack endpoints exist only when DEMO_MODE is on.
"""
from fastapi import HTTPException, Security, status
from fastapi.security import APIKeyHeader, HTTPAuthorizationCredentials, HTTPBearer

import config
from services import auth

_agent_key_header = APIKeyHeader(name="X-API-KEY", auto_error=False)
_bearer = HTTPBearer(auto_error=False)


def require_agent(api_key: str = Security(_agent_key_header)) -> str:
    agent = auth.verify_agent_key(api_key)
    if not agent:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                            detail="Invalid or missing agent API key")
    return agent


def require_admin(creds: HTTPAuthorizationCredentials = Security(_bearer)) -> dict:
    claims = auth.verify_token(creds.credentials) if creds else None
    if not claims or claims.get("role") != "admin":
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                            detail="Login required or session expired",
                            headers={"WWW-Authenticate": "Bearer"})
    return claims


def require_demo():
    if not config.DEMO_MODE:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Not Found")