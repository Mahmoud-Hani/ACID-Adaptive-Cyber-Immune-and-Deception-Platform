from datetime import datetime, timezone
from pathlib import Path

import pytest

from parser.normalizer.suricata_normalizer import normalize_suricata_flow
from parser.normalizer.zeek_normalizer import normalize_zeek_conn
from parser.suricata.eve_reader import read_eve_json
from parser.zeek.conn_reader import read_conn_log

FIXTURES = Path(__file__).resolve().parent.parent / "parser" / "fixtures"
ZEEK_FIXTURE = FIXTURES / "zeek-conn-portscan.log"
EVE_FIXTURE = FIXTURES / "suricata-eve-sample.json"

T0 = datetime(2025, 11, 20, 12, 0, 1, 120000, tzinfo=timezone.utc)


def zeek_events():
    return [normalize_zeek_conn(r, "zeek-01") for r in read_conn_log(ZEEK_FIXTURE)]


def suricata_flow_events():
    # The event_type filter lives here only until stage 6 handles it properly.
    return [
        normalize_suricata_flow(r, "suricata-01")
        for r in read_eve_json(EVE_FIXTURE)
        if r.data["event_type"] == "flow"
    ]


def test_zeek_s0_record_maps_fields_and_keeps_nulls():
    e = zeek_events()[0]
    assert e.timestamp == T0
    assert e.event_type == "network_connection"
    assert e.source_ip == "10.10.10.20"
    assert e.source_port == 40122
    assert e.destination_ip == "10.10.10.30"
    assert e.destination_port == 21
    assert e.protocol == "tcp"
    assert e.source_packets == 1
    assert e.destination_packets == 0
    assert e.duration is None
    assert e.source_bytes is None
    assert e.sensor_id == "zeek-01"
    assert e.event_version == "1.0"
    assert e.event_id is None and e.raw_ref is None


def test_zeek_rej_record_keeps_duration_and_bytes():
    e = zeek_events()[2]
    assert e.duration == pytest.approx(0.0004)
    assert e.source_bytes == 0
    assert e.destination_bytes == 0
    assert e.destination_packets == 1


def test_suricata_flow_maps_fields_and_lowercases_protocol():
    e = suricata_flow_events()[0]
    assert e.timestamp == T0
    assert e.source_ip == "10.10.10.20"
    assert e.source_port == 40122
    assert e.destination_port == 21
    assert e.protocol == "tcp"
    assert e.duration == 0.0
    assert e.source_packets == 1
    assert e.destination_packets == 0
    assert e.source_bytes == 74
    assert e.destination_bytes == 0
    assert e.sensor_id == "suricata-01"


def test_suricata_flow_duration_is_end_minus_start():
    e = suricata_flow_events()[2]
    assert e.duration == pytest.approx(0.0004)


def test_zeek_and_suricata_agree_on_the_same_connection():
    z = zeek_events()[0]
    s = suricata_flow_events()[0]
    assert z.timestamp == s.timestamp
    assert z.source_ip == s.source_ip
    assert z.destination_ip == s.destination_ip
    assert z.destination_port == s.destination_port
    assert z.protocol == s.protocol