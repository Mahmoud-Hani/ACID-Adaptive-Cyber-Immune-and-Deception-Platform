"""Shared container for one raw telemetry record."""

from dataclasses import dataclass


@dataclass(frozen=True)
class RawRecord:
    """One raw sensor record plus where it came from."""

    line_number: int  # 1-based, used later to build raw_ref
    data: dict        # the parsed JSON object, untouched