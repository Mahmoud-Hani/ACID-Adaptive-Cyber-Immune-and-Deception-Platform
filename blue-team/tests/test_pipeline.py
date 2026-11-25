from pathlib import Path

from parser.normalizer.event import Event
from parser.pipeline import process_suricata_eve, process_zeek_conn
from parser.results import Rejected, Skipped

FIXTURES = Path(__file__).resolve().parent.parent / "parser" / "fixtures"


def split(results):
    events = [r for r in results if isinstance(r, Event)]
    rejected = {r.line_number: r.reason for r in results if isinstance(r, Rejected)}
    skipped = [r.line_number for r in results if isinstance(r, Skipped)]
    return events, rejected, skipped


def test_valid_zeek_fixture_has_no_rejects_or_skips():
    events, rejected, skipped = split(
        list(process_zeek_conn(FIXTURES / "zeek-conn-portscan.log", "zeek-01"))
    )
    assert len(events) == 5
    assert rejected == {} and skipped == []


def test_valid_suricata_sample_skips_non_flow_events():
    events, rejected, skipped = split(
        list(process_suricata_eve(FIXTURES / "suricata-eve-sample.json", "suricata-01"))
    )
    assert len(events) == 3
    assert rejected == {}
    assert skipped == [4, 5]  # the alert and the stats lines


def test_zeek_invalid_fixture_never_stops_the_run():
    events, rejected, skipped = split(
        list(process_zeek_conn(FIXTURES / "zeek-conn-invalid.log", "zeek-01"))
    )
    assert [e.destination_port for e in events] == [21, 443]
    assert sorted(rejected) == [2, 3, 4, 6]
    assert "malformed JSON" in rejected[2]
    assert "id.orig_h" in rejected[3]
    assert "destination_port" in rejected[4]
    assert "source_ip" in rejected[6]
    assert skipped == [5]


def test_suricata_invalid_fixture_never_stops_the_run():
    events, rejected, skipped = split(
        list(process_suricata_eve(FIXTURES / "suricata-eve-invalid.json", "suricata-01"))
    )
    assert [e.destination_port for e in events] == [21, 22]
    assert sorted(rejected) == [2, 3, 4]
    assert "malformed JSON" in rejected[2]
    assert "dest_ip" in rejected[3]
    assert "destination_port" in rejected[4]
    assert skipped == [5]