
import importlib.util
from pathlib import Path

from fastapi.testclient import TestClient


ROOT = Path(__file__).resolve().parents[2]
MAIN_PATH = ROOT / "ai" / "future-ml-memory" / "main.py"

spec = importlib.util.spec_from_file_location("acid_api", MAIN_PATH)
api_module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(api_module)

client = TestClient(api_module.app)


def test_health_endpoint():
    response = client.get("/health")

    assert response.status_code == 200
    assert response.json() == {"status": "healthy"}


def test_predict_endpoint():
    payload = {
        "event_id": "evt-001",
        "src_port": 52344,
        "dst_port": 22,
        "protocol": "tcp",
        "event_type": "network_connection",
    }

    response = client.post("/predict", json=payload)

    assert response.status_code == 200
    assert response.json()["ml_risk_score"] == 0.85


def test_predict_requires_event_id():
    payload = {
        "dst_port": 22,
        "protocol": "tcp",
    }

    response = client.post("/predict", json=payload)

    assert response.status_code == 422


def test_predict_returns_mock_score():
    payload = {"event_id": "evt-002"}

    response = client.post("/predict", json=payload)

    assert response.json() == {"ml_risk_score": 0.85}
