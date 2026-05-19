from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from database import engine, Base
import models
from routes import logs, verify, merkle, dashboard

Base.metadata.create_all(bind=engine)

app = FastAPI(title="Secure Log Management System")

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

@app.get("/")
def home():
    return {
        "message": "Secure Log Management System is running"
    }