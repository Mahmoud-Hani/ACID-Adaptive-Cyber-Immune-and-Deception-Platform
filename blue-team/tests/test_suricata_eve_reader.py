from collections import Counter
from pathlib import Path

from parser.suricata.eve_reader import read_eve_json

FIXTURE = (
    Path(__file__).resolve().parent.parent
    / "parser" / "fixtures" / "suricata-eve-sample.json"
)


def test_reads_all_records():
    records = list(read_eve_json(FIXTURE))
    assert len(records) == 5


def test_first_record_keeps_line_number_and_raw_fields():
    first = next(read_eve_json(FIXTURE))
    assert first.line_number == 1
    assert first.data["event_type"] == "flow"
    assert first.data["src_ip"] == "10.10.10.20"
    assert first.data["dest_port"] == 21
    assert first.data["flow"]["pkts_toserver"] == 1


def test_reader_does_not_filter_event_types():
    types = Counter(r.data["event_type"] for r in read_eve_json(FIXTURE))
    assert types == {"flow": 3, "alert": 1, "stats": 1}


def test_stats_record_has_no_ip_fields():
    last = list(read_eve_json(FIXTURE))[-1]
    assert last.data["event_type"] == "stats"
    assert "src_ip" not in last.data