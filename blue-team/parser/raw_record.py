"""Shared containers for raw telemetry lines."""

from dataclasses import dataclass


@dataclass(frozen=True)
class RawRecord:
    """One raw sensor record plus where it came from."""

    line_number: int  # 1-based, used later to build raw_ref
    data: dict        # the parsed JSON object, untouched


@dataclass(frozen=True)
class MalformedLine:
    """A line that could not be read as a JSON object."""

    line_number: int
    raw_text: str
    error: str