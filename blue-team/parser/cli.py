"""Command line entry point: raw log -> normalized Events as JSON.

Example:
    python -m parser.cli zeek parser/fixtures/zeek-conn-portscan.log \
        --sensor-id zeek-01 --dataset scan_01 --out out.json
"""

import argparse
import json
import sys
from dataclasses import asdict, is_dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, Sequence

from parser.normalizer.event import Event
from parser.pipeline import process_suricata_eve, process_zeek_conn
from parser.results import Rejected, Skipped

_TS_FORMAT = "%Y-%m-%dT%H:%M:%S.%fZ"  # same format used for event_id


def _jsonable(value):
    if isinstance(value, datetime):
        return value.astimezone(timezone.utc).strftime(_TS_FORMAT)
    raise TypeError(f"not serializable: {type(value)!r}")


def run(source: str, path: Path, sensor_id: str, dataset: str) -> dict:
    processor = process_zeek_conn if source == "zeek" else process_suricata_eve
    events, rejected, skipped = [], [], []
    for item in processor(path, sensor_id, dataset):
        if isinstance(item, Event):
            events.append(asdict(item))
        elif isinstance(item, Rejected):
            rejected.append(asdict(item) if is_dataclass(item) else vars(item))
        elif isinstance(item, Skipped):
            skipped.append(asdict(item) if is_dataclass(item) else vars(item))
    return {
        "summary": {
            "source": source,
            "dataset": dataset,
            "sensor_id": sensor_id,
            "events": len(events),
            "rejected": len(rejected),
            "skipped": len(skipped),
        },
        "events": events,
        "rejected": rejected,
        "skipped": skipped,
    }


def main(argv: Optional[Sequence[str]] = None) -> int:
    ap = argparse.ArgumentParser(description="ACID parser: raw log -> Event JSON")
    ap.add_argument("source", choices=["zeek", "suricata"])
    ap.add_argument("path", type=Path)
    ap.add_argument("--sensor-id", required=True)
    ap.add_argument("--dataset", required=True)
    ap.add_argument("--out", type=Path, help="write JSON here instead of stdout")
    args = ap.parse_args(argv)

    result = run(args.source, args.path, args.sensor_id, args.dataset)
    text = json.dumps(result, indent=2, default=_jsonable, ensure_ascii=False) + "\n"
    if args.out:
        args.out.write_text(text, encoding="utf-8", newline="\n")
    else:
        sys.stdout.write(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())