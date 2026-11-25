"""Stable raw_ref and event_id for ACID Events.

event_id formula (frozen, see docs/telemetry-field-map.md section 14):

    "evt_" + first 32 hex chars of SHA-256 over
    sensor_id|timestamp|source_ip|source_port|destination_ip|destination_port|protocol|event_type
"""

import hashlib
from datetime import timezone

from parser.normalizer.event import Event

_TS_FORMAT = "%Y-%m-%dT%H:%M:%S.%fZ"


def event_id_basis(event: Event) -> str:
    """The exact text that gets hashed. Kept separate so it can be tested."""
    if event.timestamp.tzinfo is None:
        raise ValueError("timestamp must be timezone-aware (UTC)")
    parts = [
        event.sensor_id,
        event.timestamp.astimezone(timezone.utc).strftime(_TS_FORMAT),
        event.source_ip,
        "" if event.source_port is None else str(event.source_port),
        event.destination_ip,
        str(event.destination_port),
        event.protocol,
        event.event_type,
    ]
    return "|".join(parts)


def compute_event_id(event: Event) -> str:
    digest = hashlib.sha256(event_id_basis(event).encode("utf-8")).hexdigest()
    return "evt_" + digest[:32]


def build_raw_ref(scheme: str, dataset: str, log_name: str, line_number: int) -> str:
    """Build e.g. zeek://scan_01/conn.log#line-101 (format from the field map)."""
    if not dataset or any(ch in dataset for ch in "/#| "):
        raise ValueError(f"invalid dataset name: {dataset!r}")
    return f"{scheme}://{dataset}/{log_name}#line-{line_number}"