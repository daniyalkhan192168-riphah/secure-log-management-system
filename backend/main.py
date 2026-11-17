from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware

import config
from database import engine, Base, check_schema
import models  # noqa: F401  (registers tables before create_all)
from routes import agents, auth, logs, verify, merkle, dashboard, keys
from services import key_manager
from services.monitor import monitor

missing = config.missing_security_settings()
if missing:
    raise RuntimeError(
        "Security settings are missing: " + ", ".join(missing) +
        ".\nRun this once in the backend folder:   python manage.py init"
    )

check_schema()
Base.metadata.create_all(bind=engine)
key_manager.initialize()


@asynccontextmanager
async def lifespan(app: FastAPI):
    monitor.start()          # background integrity checks
    yield
    monitor.stop()


app = FastAPI(
    title="Secure Log Management System",
    description="Tamper-evident logging with hash chaining, Merkle trees and forward-secure HMAC seals",
    version="2.2.0",
    docs_url="/docs" if config.ENABLE_DOCS else None,
    redoc_url=None,
    openapi_url="/openapi.json" if config.ENABLE_DOCS else None,
    lifespan=lifespan,
)

# Only the dashboard's own origin may call the API from a browser.
app.add_middleware(
    CORSMiddleware,
    allow_origins=config.CORS_ORIGINS,
    allow_methods=["GET", "POST", "PUT"],
    allow_headers=["Authorization", "Content-Type", "X-API-KEY"],
)


@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Cache-Control"] = "no-store"
    return response


for module in (agents, auth, logs, verify, merkle, dashboard, keys):
    app.include_router(module.router)


@app.get("/")
def root():
    return {"message": "Secure Log Management API is running"}


print(f"[SecureLog] demo mode: {'ON' if config.DEMO_MODE else 'OFF'} | "
      f"docs: {'ON' if config.ENABLE_DOCS else 'OFF'} | "
      f"integrity check every {config.INTEGRITY_CHECK_SECONDS}s | "
      f"CORS: {', '.join(config.CORS_ORIGINS)}")