"""Zeek conn.log reader.

Reads a Zeek JSON conn.log and yields each record together with its
line number. No normalization and no error handling yet (stage 6).
"""

import json
from pathlib import Path
from typing import Iterator, Union

from parser.raw_record import RawRecord


def read_conn_log(path: Union[str, Path]) -> Iterator[RawRecord]:
    """Yield a RawRecord for every non-empty line of a Zeek JSON conn.log."""
    with Path(path).open("r", encoding="utf-8") as f:
        for line_number, line in enumerate(f, start=1):
            line = line.strip()
            if not line:
                continue
            yield RawRecord(line_number=line_number, data=json.loads(line))