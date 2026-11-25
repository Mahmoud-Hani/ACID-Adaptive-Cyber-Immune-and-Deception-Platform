"""Read a log file and turn every line into an Event, Rejected or Skipped.

A bad line never stops the run: it becomes a Rejected result with a reason.
Every valid Event gets its raw_ref and event_id here.
"""

import json
from dataclasses import replace
from pathlib import Path
from typing import Callable, Iterator, Optional, Union

from parser.normalizer.event import Event
from parser.normalizer.identity import build_raw_ref, compute_event_id
from parser.normalizer.suricata_normalizer import normalize_suricata_flow
from parser.normalizer.validation import SUPPORTED_PROTOCOLS, validate_event
from parser.normalizer.zeek_normalizer import normalize_zeek_conn
from parser.raw_record import MalformedLine, RawRecord
from parser.results import Rejected, Skipped
from parser.suricata.eve_reader import read_eve_json
from parser.zeek.conn_reader import read_conn_log

Result = Union[Event, Rejected, Skipped]


def _normalize_or_reject(
    normalizer: Callable[[RawRecord, str], Event],
    record: RawRecord,
    sensor_id: str,
    raw_ref: str,
) -> Union[Event, Rejected]:
    try:
        event = normalizer(record, sensor_id)
        validate_event(event)
        event = replace(event, raw_ref=raw_ref)
        return replace(event, event_id=compute_event_id(event))
    except KeyError as exc:
        reason = f"missing required field: {exc.args[0]}"
    except (TypeError, ValueError, AttributeError, OverflowError, OSError) as exc:
        reason = f"invalid value: {exc}"
    return Rejected(record.line_number, reason, json.dumps(record.data))


def _protocol_skip(record: RawRecord) -> Optional[Skipped]:
    proto = record.data.get("proto")
    if isinstance(proto, str) and proto.lower() not in SUPPORTED_PROTOCOLS:
        return Skipped(
            record.line_number,
            f"unsupported protocol {proto.lower()!r} (only tcp/udp for now)",
        )
    return None


def process_zeek_conn(
    path: Union[str, Path], sensor_id: str, dataset: str
) -> Iterator[Result]:
    for item in read_conn_log(path):
        if isinstance(item, MalformedLine):
            yield Rejected(item.line_number, f"malformed JSON: {item.error}", item.raw_text)
            continue
        skipped = _protocol_skip(item)
        if skipped:
            yield skipped
            continue
        raw_ref = build_raw_ref("zeek", dataset, "conn.log", item.line_number)
        yield _normalize_or_reject(normalize_zeek_conn, item, sensor_id, raw_ref)


def process_suricata_eve(
    path: Union[str, Path], sensor_id: str, dataset: str
) -> Iterator[Result]:
    for item in read_eve_json(path):
        if isinstance(item, MalformedLine):
            yield Rejected(item.line_number, f"malformed JSON: {item.error}", item.raw_text)
            continue
        event_type = item.data.get("event_type")
        if event_type != "flow":
            yield Skipped(item.line_number, f"unsupported event_type {event_type!r}")
            continue
        skipped = _protocol_skip(item)
        if skipped:
            yield skipped
            continue
        raw_ref = build_raw_ref("suricata", dataset, "eve.json", item.line_number)
        yield _normalize_or_reject(normalize_suricata_flow, item, sensor_id, raw_ref)