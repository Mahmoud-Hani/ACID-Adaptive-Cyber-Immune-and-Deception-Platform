"""Normalize a Zeek conn.log record into an ACID Event."""

from datetime import datetime, timezone

from parser.normalizer.event import Event
from parser.raw_record import RawRecord


def normalize_zeek_conn(record: RawRecord, sensor_id: str) -> Event:
    d = record.data
    return Event(
        timestamp=datetime.fromtimestamp(d["ts"], tz=timezone.utc),
        event_type="network_connection",
        source_ip=d["id.orig_h"],
        source_port=d.get("id.orig_p"),
        destination_ip=d["id.resp_h"],
        destination_port=d["id.resp_p"],
        protocol=d["proto"].lower(),
        duration=d.get("duration"),
        source_packets=d.get("orig_pkts"),
        destination_packets=d.get("resp_pkts"),
        source_bytes=d.get("orig_bytes"),
        destination_bytes=d.get("resp_bytes"),
        sensor_id=sensor_id,
    )