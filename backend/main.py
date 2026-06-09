from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from database import engine, Base
from routes import logs, verify, merkle, dashboard, keys
from security import api_key_header  # just import, don't redefine
import routes.logs
print("LOADED LOGS FILE:", routes.logs.__file__)
Base.metadata.create_all(bind=engine)

app = FastAPI(
    title="Secure Log Management System",
    description="A tamper-evident logging system using Merkle Trees and Hash Chaining",
    version="1.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(logs.router)
app.include_router(verify.router)
app.include_router(merkle.router)
app.include_router(dashboard.router)
app.include_router(keys.router)

@app.get("/")
def root():
    return {"message": "Secure Log Management API is running"}