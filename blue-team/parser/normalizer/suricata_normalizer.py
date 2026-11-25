"""Normalize a Suricata EVE `flow` record into an ACID Event."""

from datetime import datetime, timezone
from typing import Optional

from parser.normalizer.event import Event
from parser.raw_record import RawRecord

# Suricata writes timestamps like 2025-11-20T12:00:01.120000+0000
_TS_FORMAT = "%Y-%m-%dT%H:%M:%S.%f%z"


def _parse_ts(value: str) -> datetime:
    return datetime.strptime(value, _TS_FORMAT).astimezone(timezone.utc)


def _duration_seconds(flow: dict) -> Optional[float]:
    start, end = flow.get("start"), flow.get("end")
    if start is None or end is None:
        return None
    return (_parse_ts(end) - _parse_ts(start)).total_seconds()


def normalize_suricata_flow(record: RawRecord, sensor_id: str) -> Event:
    d = record.data
    flow = d.get("flow", {})
    return Event(
        timestamp=_parse_ts(d["timestamp"]),
        event_type="network_connection",
        source_ip=d["src_ip"],
        source_port=d.get("src_port"),
        destination_ip=d["dest_ip"],
        destination_port=d["dest_port"],
        protocol=d["proto"].lower(),
        duration=_duration_seconds(flow),
        source_packets=flow.get("pkts_toserver"),
        destination_packets=flow.get("pkts_toclient"),
        source_bytes=flow.get("bytes_toserver"),
        destination_bytes=flow.get("bytes_toclient"),
        sensor_id=sensor_id,
    )