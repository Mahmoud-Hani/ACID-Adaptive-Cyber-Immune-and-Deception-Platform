"""Suricata EVE JSON reader.

Reads a Suricata eve.json (one JSON object per line) and yields every
record together with its line number. It does NOT filter by event_type:
deciding which events are usable is the job of stage 6 (unknown events).
"""

import json
from pathlib import Path
from typing import Iterator, Union

from parser.raw_record import RawRecord


def read_eve_json(path: Union[str, Path]) -> Iterator[RawRecord]:
    """Yield a RawRecord for every non-empty line of a Suricata eve.json."""
    with Path(path).open("r", encoding="utf-8") as f:
        for line_number, line in enumerate(f, start=1):
            line = line.strip()
            if not line:
                continue
            yield RawRecord(line_number=line_number, data=json.loads(line))