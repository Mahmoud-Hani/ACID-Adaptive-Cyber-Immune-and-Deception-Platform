"""Value checks taken from docs/telemetry-field-map.md."""

import ipaddress

from parser.normalizer.event import Event

SUPPORTED_PROTOCOLS = {"tcp", "udp"}  # ICMP waits for the Backend decision


def _check_ip(name: str, value) -> None:
    if not isinstance(value, str):
        raise ValueError(f"{name} must be a string, got {value!r}")
    try:
        ipaddress.ip_address(value)
    except ValueError:
        raise ValueError(f"{name} is not a valid IP address: {value!r}") from None


def _check_port(name: str, value) -> None:
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= 65535:
        raise ValueError(f"{name} must be an integer between 0 and 65535, got {value!r}")


def validate_event(event: Event) -> None:
    """Raise ValueError (with a clear message) if the Event is invalid."""
    _check_ip("source_ip", event.source_ip)
    _check_ip("destination_ip", event.destination_ip)
    _check_port("destination_port", event.destination_port)
    if event.source_port is not None:
        _check_port("source_port", event.source_port)
    if event.protocol not in SUPPORTED_PROTOCOLS:
        raise ValueError(f"unsupported protocol: {event.protocol!r}")