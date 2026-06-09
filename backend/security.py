from fastapi import Security, HTTPException, status
from fastapi.security import APIKeyHeader

API_KEY = "secure-log-secret-2026"
api_key_header = APIKeyHeader(name="X-API-KEY")

def get_api_key(api_key: str = Security(api_key_header)):
    if api_key == API_KEY:
        return api_key
    raise HTTPException(
        status_code=status.HTTP_403_FORBIDDEN,
        detail="Invalid or missing API Key"
    )