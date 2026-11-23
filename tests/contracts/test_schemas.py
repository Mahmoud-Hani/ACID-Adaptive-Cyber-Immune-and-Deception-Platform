
import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator, FormatChecker
from jsonschema.exceptions import ValidationError


ROOT = Path(__file__).resolve().parents[2]
SCHEMA_DIR = ROOT / "contracts" / "v1" / "schemas"
FORMAT_CHECKER = FormatChecker()


def load_schema(name):
    schema_path = SCHEMA_DIR / f"{name}.schema.json"
    with schema_path.open(encoding="utf-8") as file:
        return json.load(file)


def validate_payload(schema_name, payload):
    schema = load_schema(schema_name)
    validator = Draft202012Validator(
        schema,
        format_checker=FORMAT_CHECKER,
    )
    validator.validate(payload)


VALID_EVENT = {
    "event_id": "evt-001",
    "timestamp": "2026-11-24T10:30:00Z",
    "event_type": "network_connection",
    "source": "firewall",
    "src_ip": "192.168.1.10",
    "dst_ip": "192.168.1.20",
    "src_port": 52344,
    "dst_port": 22,
    "protocol": "tcp",
    "raw_data": {},
}

VALID_DETECTION = {
    "detection_id": "det-001",
    "event_id": "evt-001",
    "detection_type": "ssh_bruteforce",
    "severity": "high",
    "confidence": 0.95,
    "description": "Multiple failed SSH authentication attempts",
    "timestamp": "2026-11-24T10:35:00Z",
    "technique": "T1110.001",
    "techniques": ["T1110.001"],
}

VALID_INCIDENT = {
    "incident_id": "inc-001",
    "title": "SSH Brute Force Activity",
    "status": "open",
    "severity": "high",
    "detection_ids": ["det-001"],
    "created_at": "2026-11-24T10:35:00Z",
    "updated_at": "2026-11-24T10:35:00Z",
    "description": "Repeated SSH authentication failures",
}


# Event tests

def test_valid_event():
    validate_payload("event", VALID_EVENT)


def test_event_missing_required_field():
    payload = VALID_EVENT.copy()
    payload.pop("event_id")

    with pytest.raises(ValidationError):
        validate_payload("event", payload)


# Detection tests

def test_valid_detection():
    validate_payload("detection", VALID_DETECTION)


def test_detection_missing_required_field():
    payload = VALID_DETECTION.copy()
    payload.pop("detection_id")

    with pytest.raises(ValidationError):
        validate_payload("detection", payload)


def test_ssh_bruteforce_detection_type():
    payload = VALID_DETECTION.copy()
    payload["detection_type"] = "ssh_bruteforce"

    validate_payload("detection", payload)


def test_valid_mitre_technique():
    payload = VALID_DETECTION.copy()
    payload["technique"] = "T1110.001"

    validate_payload("detection", payload)


def test_invalid_mitre_technique():
    payload = VALID_DETECTION.copy()
    payload["technique"] = "T9999"

    with pytest.raises(ValidationError):
        validate_payload("detection", payload)


def test_multiple_mitre_techniques():
    payload = VALID_DETECTION.copy()
    payload["techniques"] = ["T1046", "T1110.001"]

    validate_payload("detection", payload)


# Incident tests

def test_valid_incident():
    validate_payload("incident", VALID_INCIDENT)


def test_incident_missing_required_field():
    payload = VALID_INCIDENT.copy()
    payload.pop("incident_id")

    with pytest.raises(ValidationError):
        validate_payload("incident", payload)
