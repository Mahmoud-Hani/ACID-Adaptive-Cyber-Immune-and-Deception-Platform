from datetime import datetime, timezone
import json
from pathlib import Path
from typing import List, Optional

from fastapi import FastAPI
from pydantic import BaseModel, Field

app = FastAPI(
    title="ACID CTI Enrichment Service",
    description="Offline-first CTI Enrichment API reading from deterministic fixtures",
    version="1.0.0",
)

FIXTURES_DIR = Path(__file__).resolve().parent.parent / "fixtures"


def load_fixture_file(filename: str) -> dict:
    file_path = FIXTURES_DIR / filename
    with open(file_path, "r", encoding="utf-8") as f:
        return json.load(f)


class EnrichRequest(BaseModel):
    indicator: str = Field(..., min_length=1)
    indicator_type: str = Field(default="ipv4")
    incident_id: Optional[str] = Field(default=None)


class EnrichResponse(BaseModel):
    indicator: str
    match: bool
    source: str
    tags: List[str]
    confidence: float
    fetched_at: str
    stale: bool
    error: Optional[str] = None


@app.get("/health")
def health_check():
    return {"status": "ok", "provider": "offline-fixture"}


@app.post("/enrich", response_model=EnrichResponse)
def enrich_indicator(payload: EnrichRequest):
    now_iso = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    indicator = payload.indicator.strip()

    if indicator == "10.10.10.20":
        data = load_fixture_file("cti-hit.json")
    elif indicator == "192.0.2.99":
        data = load_fixture_file("cti-offline.json")
    else:
        data = load_fixture_file("cti-no-hit.json")

    return EnrichResponse(
        indicator=indicator,
        match=data.get("match", False),
        source=data.get("source", "offline-fixture"),
        tags=data.get("tags", []),
        confidence=data.get("confidence", 0.0),
        fetched_at=now_iso,
        stale=data.get("stale", False),
        error=data.get("error", None),
    )