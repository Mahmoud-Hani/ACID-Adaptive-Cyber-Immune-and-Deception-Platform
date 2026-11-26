import json
from pathlib import Path

from parser.cli import main, run

ROOT = Path(__file__).resolve().parent.parent / "parser" / "fixtures"
ZEEK_FIXTURE = ROOT / "zeek-conn-portscan.log"
EVE_FIXTURE = ROOT / "suricata-eve-sample.json"
EXPECTED = ROOT / "expected"


def test_zeek_output_matches_golden_file(tmp_path):
    out = tmp_path / "out.json"
    main(["zeek", str(ZEEK_FIXTURE), "--sensor-id", "zeek-01",
          "--dataset", "scan_01", "--out", str(out)])
    assert out.read_text(encoding="utf-8") == (
        EXPECTED / "scan_01-zeek-events.json"
    ).read_text(encoding="utf-8")


def test_suricata_output_matches_golden_file(tmp_path):
    out = tmp_path / "out.json"
    main(["suricata", str(EVE_FIXTURE), "--sensor-id", "suricata-01",
          "--dataset", "scan_01", "--out", str(out)])
    assert out.read_text(encoding="utf-8") == (
        EXPECTED / "scan_01-suricata-events.json"
    ).read_text(encoding="utf-8")


def test_summary_counts_match_lists():
    result = run("zeek", ZEEK_FIXTURE, "zeek-01", "scan_01")
    s = result["summary"]
    assert s["events"] == len(result["events"]) == 5
    assert s["rejected"] == len(result["rejected"]) == 0


def test_every_event_is_traceable():
    result = run("zeek", ZEEK_FIXTURE, "zeek-01", "scan_01")
    for e in result["events"]:
        assert e["event_id"].startswith("evt_")
        assert e["raw_ref"].startswith("zeek://scan_01/conn.log#line-")


def test_output_is_valid_json_on_stdout(capsys):
    main(["zeek", str(ZEEK_FIXTURE), "--sensor-id", "zeek-01", "--dataset", "scan_01"])
    assert json.loads(capsys.readouterr().out)["summary"]["events"] == 5