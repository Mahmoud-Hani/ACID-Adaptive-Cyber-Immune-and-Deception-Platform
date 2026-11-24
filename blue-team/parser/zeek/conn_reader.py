"""Zeek conn.log reader.

Stage 3 scope: read a Zeek JSON conn.log and yield each record together
with its line number. No normalization and no error handling yet.
"""

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator, Union


@dataclass(frozen=True)
class RawRecord:
    """One raw Zeek record plus where it came from."""

    line_number: int  # 1-based, used later to build raw_ref
    data: dict        # the parsed JSON object, untouched


def read_conn_log(path: Union[str, Path]) -> Iterator[RawRecord]:
    """Yield a RawRecord for every non-empty line of a Zeek JSON conn.log."""
    with Path(path).open("r", encoding="utf-8") as f:
        for line_number, line in enumerate(f, start=1):
            line = line.strip()
            if not line:
                continue
            yield RawRecord(line_number=line_number, data=json.loads(line))