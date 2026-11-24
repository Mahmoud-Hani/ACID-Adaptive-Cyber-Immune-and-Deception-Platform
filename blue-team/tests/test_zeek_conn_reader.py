from pathlib import Path

from parser.zeek.conn_reader import read_conn_log

FIXTURE = (
    Path(__file__).resolve().parent.parent
    / "parser" / "fixtures" / "zeek-conn-portscan.log"
)


def test_reads_all_records():
    records = list(read_conn_log(FIXTURE))
    assert len(records) == 5


def test_first_record_keeps_line_number_and_raw_fields():
    first = next(read_conn_log(FIXTURE))
    assert first.line_number == 1
    assert first.data["id.orig_h"] == "10.10.10.20"
    assert first.data["id.resp_p"] == 21
    assert first.data["conn_state"] == "S0"


def test_s0_record_has_no_duration():
    first = next(read_conn_log(FIXTURE))
    assert "duration" not in first.data