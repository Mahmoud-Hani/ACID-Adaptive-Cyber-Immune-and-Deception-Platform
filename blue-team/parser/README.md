# ACID Parser (Blue 1)

Converts Zeek `conn.log` (JSON) and Suricata `eve.json` flow records into
ACID Event objects. Field mapping: `docs/telemetry-field-map.md`.



## Run
    cd blue-team
    python -m parser.cli zeek parser/fixtures/zeek-conn-portscan.log --sensor-id zeek-01 --dataset scan_01
    python -m parser.cli suricata parser/fixtures/suricata-eve-sample.json --sensor-id suricata-01 --dataset scan_01



## Test
    python -m pytest -v        # expected: 43 passed



## Output
JSON with `summary`, `events`, `rejected`, `skipped`.
Reference outputs: `parser/fixtures/expected/`.



## event_id
`"evt_" + sha256(sensor_id|timestamp|source_ip|source_port|destination_ip|destination_port|protocol|event_type)[:32]`
Timestamp is UTC, `YYYY-MM-DDTHH:MM:SS.ffffffZ`; empty source_port is an empty string.
Reference: zeek-01, 2025-11-20T12:00:01.120000Z, 10.10.10.20:40122 -> 10.10.10.30:21 tcp network_connection
= `evt_b678fd51a39581ac506c2c20a5c69db0`



## Known limitations
- Only tcp/udp; ICMP is skipped (pending Backend decision on icmp_type/icmp_code).
- Suricata: only `flow` records are normalized; alerts are skipped.
- Rejected/Skipped results carry `line_number` but no `raw_ref`.
