"""Suricata EVE JSON reader.

Reads a Suricata eve.json and yields each line as a RawRecord, or as a
MalformedLine when the line is not a valid JSON object. It does NOT
filter by event_type (that is done in parser/pipeline.py).
"""

import json
from pathlib import Path
from typing import Iterator, Union

from parser.raw_record import MalformedLine, RawRecord


def read_eve_json(path: Union[str, Path]) -> Iterator[Union[RawRecord, MalformedLine]]:
    with Path(path).open("r", encoding="utf-8") as f:
        for line_number, line in enumerate(f, start=1):
            line = line.strip()
            if not line:
                continue
            try:
                data = json.loads(line)
            except json.JSONDecodeError as exc:
                yield MalformedLine(line_number, line, str(exc))
                continue
            if not isinstance(data, dict):
                yield MalformedLine(line_number, line, "JSON value is not an object")
                continue
            yield RawRecord(line_number=line_number, data=data)