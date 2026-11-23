
from fastapi import FastAPI
from pydantic import BaseModel
from typing import Optional


app = FastAPI(
    title="ACID Future ML Memory API",
    description="Mock API for future ML risk scoring integration",
    version="0.1.0",
)


class PredictionRequest(BaseModel):
    event_id: str
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    protocol: Optional[str] = None
    event_type: Optional[str] = None


class PredictionResponse(BaseModel):
    ml_risk_score: float


@app.get("/health")
def health_check():
    return {"status": "healthy"}


@app.post("/predict", response_model=PredictionResponse)
def predict(request: PredictionRequest):
    # Mock response only: no real ML inference is performed.
    return PredictionResponse(ml_risk_score=0.85)
