"""ACID Event v1, parser-side representation.

Field names follow docs/telemetry-field-map.md (the reference).
"""

from dataclasses import dataclass
from datetime import datetime
from typing import Optional


@dataclass(frozen=True)
class Event:
    # Required fields
    timestamp: datetime          # always UTC
    event_type: str              # "network_connection"
    source_ip: str
    destination_ip: str
    destination_port: int
    protocol: str                # lowercase: "tcp", "udp"
    sensor_id: str               # e.g. "zeek-01"

    # Optional fields (None means NULL)
    source_port: Optional[int] = None
    duration: Optional[float] = None
    source_packets: Optional[int] = None
    destination_packets: Optional[int] = None
    source_bytes: Optional[int] = None
    destination_bytes: Optional[int] = None

    # Filled in stage 7
    event_id: Optional[str] = None
    raw_ref: Optional[str] = None

    event_version: str = "1.0"