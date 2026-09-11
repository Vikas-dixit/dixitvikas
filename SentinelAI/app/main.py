from fastapi import FastAPI
from pydantic import BaseModel, Field
from typing import Optional

from app.detector import analyze_event

app = FastAPI(
    title="SentinelAI",
    description="Lightweight personal SOC API for defensive security monitoring",
    version="0.1.0",
)


class SecurityEvent(BaseModel):
    event_type: str = Field(..., examples=["login"])
    source_ip: Optional[str] = None
    username: Optional[str] = None
    success: Optional[bool] = None
    failed_attempts: int = 0
    destination_port: Optional[int] = None
    process_name: Optional[str] = None
    bytes_sent: int = 0
    destination_ip: Optional[str] = None


@app.get("/")
def root():
    return {
        "name": "SentinelAI",
        "status": "running",
        "message": "Personal SOC API is online",
    }


@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/analyze")
def analyze(event: SecurityEvent):
    return analyze_event(event.model_dump())
