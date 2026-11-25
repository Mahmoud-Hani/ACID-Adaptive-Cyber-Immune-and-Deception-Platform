from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from parser.normalizer.event import Event
from parser.normalizer.identity import build_raw_ref, compute_event_id, event_id_basis
from parser.pipeline import process_suricata_eve, process_zeek_conn

FIXTURES = Path(__file__).resolve().parent.parent / "parser" / "fixtures"
ZEEK_FIXTURE = FIXTURES / "zeek-conn-portscan.log"
EVE_FIXTURE = FIXTURES / "suricata-eve-sample.json"


def base_event(**changes) -> Event:
    event = Event(
        timestamp=datetime(2025, 11, 20, 12, 0, 1, 120000, tzinfo=timezone.utc),
        event_type="network_connection",
        source_ip="10.10.10.20",
        source_port=40122,
        destination_ip="10.10.10.30",
        destination_port=21,
        protocol="tcp",
        sensor_id="zeek-01",
    )
    return replace(event, **changes)


def test_basis_text_is_exactly_the_agreed_formula():
    assert event_id_basis(base_event()) == (
        "zeek-01|2025-11-20T12:00:01.120000Z|10.10.10.20|40122|"
        "10.10.10.30|21|tcp|network_connection"
    )


def test_event_id_golden_values():
    # If these change, the formula changed. That needs Backend approval.
    assert compute_event_id(base_event()) == "evt_b678fd51a39581ac506c2c20a5c69db0"
    assert (
        compute_event_id(base_event(sensor_id="suricata-01"))
        == "evt_88c2207f0fc04b413747a290bface40e"
    )


def test_event_id_has_expected_shape():
    event_id = compute_event_id(base_event())
    assert event_id.startswith("evt_") and len(event_id) == 36


def test_event_id_ignores_timezone_representation():
    cairo = timezone(timedelta(hours=2))
    same_moment = datetime(2025, 11, 20, 14, 0, 1, 120000, tzinfo=cairo)
    assert compute_event_id(base_event(timestamp=same_moment)) == compute_event_id(base_event())


def test_missing_source_port_is_hashed_as_empty_text():
    basis = event_id_basis(base_event(source_port=None))
    assert "|10.10.10.20||10.10.10.30|" in basis


@pytest.mark.parametrize(
    "change",
    [
        {"sensor_id": "zeek-02"},
        {"source_port": 40123},
        {"destination_port": 22},
        {"destination_ip": "10.10.10.31"},
        {"protocol": "udp"},
    ],
)
def test_different_connection_gives_different_event_id(change):
    assert compute_event_id(base_event(**change)) != compute_event_id(base_event())


def test_naive_timestamp_is_rejected():
    with pytest.raises(ValueError):
        compute_event_id(base_event(timestamp=datetime(2025, 11, 20, 12, 0, 1)))


def test_build_raw_ref_format():
    assert build_raw_ref("zeek", "scan_01", "conn.log", 101) == "zeek://scan_01/conn.log#line-101"


@pytest.mark.parametrize("bad", ["", "a/b", "a#b", "a b"])
def test_build_raw_ref_rejects_bad_dataset(bad):
    with pytest.raises(ValueError):
        build_raw_ref("zeek", bad, "conn.log", 1)


def test_pipeline_sets_raw_ref_and_event_id_on_zeek_events():
    events = list(process_zeek_conn(ZEEK_FIXTURE, "zeek-01", "scan_01"))
    assert events[0].raw_ref == "zeek://scan_01/conn.log#line-1"
    assert events[2].raw_ref == "zeek://scan_01/conn.log#line-3"
    assert events[0].event_id == "evt_b678fd51a39581ac506c2c20a5c69db0"


def test_pipeline_sets_raw_ref_on_suricata_events():
    events = list(process_suricata_eve(EVE_FIXTURE, "suricata-01", "scan_01"))
    flows = [e for e in events if hasattr(e, "raw_ref")]
    assert flows[0].raw_ref == "suricata://scan_01/eve.json#line-1"
    assert flows[0].event_id == "evt_88c2207f0fc04b413747a290bface40e"


def test_event_ids_are_unique_within_a_scan():
    events = list(process_zeek_conn(ZEEK_FIXTURE, "zeek-01", "scan_01"))
    ids = [e.event_id for e in events]
    assert len(ids) == len(set(ids)) == 5


def test_running_twice_gives_identical_event_ids():
    first = [e.event_id for e in process_zeek_conn(ZEEK_FIXTURE, "zeek-01", "scan_01")]
    second = [e.event_id for e in process_zeek_conn(ZEEK_FIXTURE, "zeek-01", "scan_01")]
    assert first == second


def test_dataset_name_does_not_change_event_id():
    a = [e.event_id for e in process_zeek_conn(ZEEK_FIXTURE, "zeek-01", "scan_01")]
    b = [e.event_id for e in process_zeek_conn(ZEEK_FIXTURE, "zeek-01", "other_run")]
    assert a == b