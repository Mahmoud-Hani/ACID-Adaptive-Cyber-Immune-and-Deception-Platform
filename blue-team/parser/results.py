"""Outcomes of parsing one line, besides a valid Event."""

from dataclasses import dataclass


@dataclass(frozen=True)
class Rejected:
    """The line is invalid. Kept (quarantined) together with the reason."""

    line_number: int
    reason: str
    raw_text: str


@dataclass(frozen=True)
class Skipped:
    """The line is valid but out of scope for now (not an error)."""

    line_number: int
    reason: str