
### 1. Timestamp

| Property         | Zeek                            | Suricata                        | ACID                       |
|       ---        |---                              |---                              |---                         |
| Raw Field        | ts                              |timestamp                        | timestamp                  |
| Data Type        | Number (Unix timestamp)         | String (ISO 8601)               | datetime2                  |
| Required         | Yes                             | Yes                             | Yes                        |
| Example          | 1795437015.123456               | 2026-11-23T12:30:15.123456+0000 | 2026-11-23T12:30:15.123456 |
| Missing Behavior | Reject                          | Reject                          | Reject                     |
| Evidence         | Preserve original log reference | Preserve original log reference | raw_ref                    |

**Normalization Rules:**
- Convert Zeek Unix timestamp to UTC DateTime.
- Parse Suricata ISO 8601 timestamp.
- Convert all timestamps to UTC before storage.
- Never replace a missing event timestamp with created_at.



### 2. Connection Identifier

| Property         | Zeek                  | Suricata                           | ACID                            |
|---               |---                    |---                                 |---                              |
| Raw Field        | uid                   | flow_id (verify availability)      | No direct field                 |
| Data Type        | String                | Must verify from actual EVE record | Not applicable                  |
| Required         | Optional              | Optional                           | Not defined                     |
| Example          | Cabc123               | Not confirmed                      | Not applicable                  |
| Missing Behavior | Keep as unavailable   | Keep as unavailable                | Do not generate a connection_id |
| Evidence         | Preserve original log | Preserve original log              | raw_ref                         |

**Normalization Notes:**
- Do not map uid to event_id.
- event_id is the ACID Event idempotency key.
- The current Backend ERD has no dedicated connection_id field.
- Any addition to the Event contract requires Backend approval.



### 3. Source IP

| Property         | Zeek                            | Suricata                        | ACID          |
|---               |---                              |---                              |---            |
| Raw Field        | `id.orig_h`                     | `src_ip`                        | `source_ip`   |
| Data Type        | String (IP address)             | String (IP address)             | `varchar(45)` |
| Required         | Yes                             |  Yes                            | Yes           |
| Example          | `10.10.10.20`                   | `10.10.10.20`                   | `10.10.10.20` |
| Missing Behavior | Reject                          | Reject                          | Reject        |
| Evidence         | Preserve original log reference | Preserve original log reference | `raw_ref`     |

**Normalization Rules:**
- Map Zeek `id.orig_h` to ACID `source_ip`.
- Map Suricata `src_ip` to ACID `source_ip`.
- Validate that the source IP is a valid IPv4 or IPv6 address.
- Reject events with a missing or invalid source IP.
- Preserve the original log reference through `raw_ref`.



### 4. Destination IP

| Property         | Zeek                            | Suricata                        | ACID             |
|---               |---                              |---                              |---               |
| Raw Field        | `id.resp_h`                     | `dest_ip`                       | `destination_ip` | 
| Data Type        | String (IP address)             | String (IP address)             | `varchar(45)`    |
| Required         | Yes                             | Yes                             |  Yes             |
| Example          | `10.10.10.30`                   | `10.10.10.30`                   | `10.10.10.30`    |
| Missing Behavior | Reject                          | Reject                          | Reject           |
| Evidence         | Preserve original log reference | Preserve original log reference | `raw_ref`        |

**Normalization Rules:**
- Map Zeek `id.resp_h` to ACID `destination_ip`.
- Map Suricata `dest_ip` to ACID `destination_ip`.
- Validate that the destination IP is a valid IPv4 or IPv6 address.
- Reject events with a missing or invalid destination IP.
- Preserve the original log reference through `raw_ref`.



### 5. Source Port

| Property         | Zeek                            | Suricata                                  | ACID          |
|---               |---                              |---                                        |---            |
| Raw Field        | `id.orig_p`                     | `src_port` (verify in actual EVE fixture) | `source_port` |
| Data Type        | Number (Port)                   | Number (Port)                             | `int`         |
| Required         | Available in connection record  | Verify availability in actual record      | Optional      |
| Example          | `40122`                         | `40122`                                   | `40122`       |
| Missing Behavior | Keep as NULL if unavailable     | Keep as NULL if unavailable               | Store NULL    |
| Evidence         | Preserve original log reference | Preserve original log reference           | `raw_ref`     |

**Normalization Rules:**
- Map Zeek `id.orig_p` to ACID `source_port`.
- Map Suricata `src_port` to ACID `source_port` when available.
- Validate that the port value is within the range 0–65535.
- If the source port is missing, store NULL instead of rejecting the event.
- Preserve the original log reference through `raw_ref`.



### 6. Destination Port

| Property         | Zeek                            | Suricata                        | ACID               |
|---               |---                              |---                              |---                 |
| Raw Field        | `id.resp_p`                     | `dest_port`                     | `destination_port` |
| Data Type        | Number (Port)                   | Number (Port)                   | `int`              |
| Required         | Yes                             | Yes                             | Yes                |
| Example          | `22`                            | `22`                            | `22`               |
| Missing Behavior | Reject                          | Reject                          | Reject             |
| Evidence         | Preserve original log reference | Preserve original log reference | `raw_ref`          |

**Normalization Rules:**
- Map Zeek `id.resp_p` to ACID `destination_port`.
- Map Suricata `dest_port` to ACID `destination_port`.
- Validate that the port value is within the range 0–65535.
- Reject events with a missing or invalid destination port.
- Preserve the original log reference through `raw_ref`.



### Protocol-Specific Port Handling

**ICMP Records:**
- Set `source_port` to `NULL`.
- Set `destination_port` to `NULL`.
- Map Zeek `id.orig_p` to `icmp_type`.
- Map Zeek `id.resp_p` to `icmp_code`.
- Map Suricata `icmp_type` to `icmp_type`.
- Map Suricata `icmp_code` to `icmp_code`.

**TCP and UDP Records:**
- `destination_port` is required.
- Set `icmp_type` and `icmp_code` to `NULL`.
- Treat TCP/UDP records without `destination_port` as malformed.
- Do not send malformed records as ACID Events.

**Port Validation Rules:**
- Port `0` is a valid port value.
- Never use port `0` to represent a missing port.
- Use `NULL` to represent the absence of a port.

**Schema Compatibility Note:**
- The approved `network_events` ERD defines `destination_port` as NOT NULL.
- The ERD does not currently define `icmp_type` or `icmp_code`.
- Backend clarification is required to resolve this contract/schema mismatch before implementing ICMP persistence.



### 7. Protocol

| Property         | Zeek                            | Suricata                        | ACID          |
|---               |---                              |---                              |---            |
| Raw Field        | `proto`                         | `proto`                         | `protocol`    |
| Data Type        | String                          | String                          | `varchar(16)` |
| Required         | Yes                             | Yes                             | Yes           |
| Example          | `tcp`                           | `TCP`                           | `tcp`         |
| Missing Behavior | Reject                          | Reject                          | Reject        |
| Evidence         | Preserve original log reference | Preserve original log reference | `raw_ref`     |

**Normalization Rules:**
- Map Zeek `proto` to ACID `protocol`.
- Map Suricata `proto` to ACID `protocol`.
- Normalize protocol values to lowercase (e.g., `TCP` → `tcp`).
- Reject events with a missing or invalid protocol value.
- Preserve the original log reference through `raw_ref`.



### 8. Duration

| Property         | Zeek                            | Suricata                        | ACID       |
|---               |---                              |---                              |---         |
| Raw Field        | `duration`                      |`flow.start` and  `flow.end`     | `duration` |
| Data Type        | Number (Seconds)                |Computed Number (Seconds)        | `float`    |
| Required         | No                              | No                              | No         |
| Example          | `0.01`                          | flow.end - flow.start           | `0.01`     |
| Missing Behavior | Store NULL                      | Store NULL                      | Store NULL |
| Evidence         | Preserve original log reference | Preserve original log reference | `raw_ref`  |

**Normalization Rules:**
- Map Zeek `duration` to ACID `duration`.
- Verify the availability and representation of duration in actual Suricata EVE records before defining its mapping.
- Store duration in seconds when the source provides a verified duration value in seconds.
- If duration is missing, store `NULL`.
- Preserve the original log reference through `raw_ref`.



### 9. Source_Packets

| Property         | Zeek                                   | Suricata                           | ACID              |
|---               |---                                     |---                                 |---                |
| Raw Field        | `orig_pkts`,                           | `flow.pkts_toserver`               | `source_packets`  |
| Data Type        | Number                                 | Number                             | `bigint`          |
| Required         | No                                     | No                                 | No                |
| Example          | ---                                    | ---                                |---                |
| Missing Behavior | Store NULL                             | Store NULL                         | Store NULL        |
| Evidence         | Preserve original log reference        | Preserve original log referen      | `raw_ref`         |
                     and directional values in raw evidence   and directional values in raw evidence

**Normalization Rules:**
- If no verified packet count is available, store `NULL`.
- Preserve the original log reference through `raw_ref`.



### 9. Destenation_Packets

| Property         | Zeek                                   | Suricata                           | ACID              |
|---               |---                                     |---                                 |---                |
| Raw Field        | `resp_pkts`,                           | `flow.pkts_toclient`             |`destination_packets`|
| Data Type        | Number                                 | Number                             | `bigint`          |
| Required         | No                                     | No                                 | No                |
| Example          | ---                                    | ---                                |---                |
| Missing Behavior | Store NULL                             | Store NULL                         | Store NULL        |
| Evidence         | Preserve original log reference        | Preserve original log referen      | `raw_ref`         |
                     and directional values in raw evidence   and directional values in raw evidence

**Normalization Rules:**
- If no verified packet count is available, store `NULL`.
- Preserve the original log reference through `raw_ref`.




### 10. SourceBytes

| Property         | Zeek                                   | Suricata                              | ACID           |
|---               |---                                     |---                                    |---             |
| Raw Field        | `orig_bytes`,                          |`flow.bytes_toserver`                  |`source_bytes`  |
| Data Type        | Number (Bytes)                         | Verify in actual EVE fixture          | `bigint`       |
| Required         | No                                     | No                                    | No             |
| Example          | `0`, `0`                               | ---                                   |---             |
| Missing Behavior | Store NULL                             | Store NULL                            | Store NULL     |
| Evidence         | Preserve original log reference        | Preserve original log reference       | `raw_ref`      |
                     and directional values in raw evidence   and directional values in raw evidence

**Normalization Rules:**
- If no verified byte count is available, store `NULL`.
- Preserve the original log reference through `raw_ref`.



### 10. DesteenationBytes

| Property         | Zeek                                   | Suricata                              | ACID           |
|---               |---                                     |---                                    |---             |
| Raw Field        |`resp_bytes`                            |`flow.bytes_toclient`               |`destenation_bytes`|
| Data Type        | Number (Bytes)                         | Verify in actual EVE fixture          | `bigint`       |
| Required         | No                                     | No                                    | No             |
| Example          | `0`, `0`                               | ---                                   |---             |
| Missing Behavior | Store NULL                             | Store NULL                            | Store NULL     |
| Evidence         | Preserve original log reference        | Preserve original log reference       | `raw_ref`      |
                     and directional values in raw evidence   and directional values in raw evidence

**Normalization Rules:**
- If no verified byte count is available, store `NULL`.
- Preserve the original log reference through `raw_ref`.



### 12. Sensor ID

| Property         | Zeek                            | Suricata                        | ACID                      |
|---               |---                              |---                              |---                        |
| Raw Field        | Configured sensor identifier    | Configured sensor identifier    | `sensor_id`               |
| Data Type        | String                          | String                          | `varchar(64)`             |
| Required         | Yes                             | Yes                             | Yes                       |
| Example          | `zeek-01`                       | `suricata-01`                   | `zeek-01` / `suricata-01` |
| Missing Behavior | Reject if sensor identity       | Reject if sensor identity       | Reject                    |
                     cannot be resolved                cannot be resolved 
| Evidence         | Preserve original log reference | Preserve original log reference | `raw_ref`                 |

**Normalization Rules:**
- Assign the configured ACID sensor identifier to each event based on its collection source.
- Map the configured identifier to ACID `sensor_id`.
- Do not use the generic sensor type (`zeek` or `suricata`) as a substitute for the configured sensor identifier unless that exact value is registered as the sensor ID.
- Ensure that the assigned `sensor_id` exists in the ACID sensor registry.
- Reject events when the sensor identity cannot be resolved.
- Preserve the original log reference through `raw_ref`.



### 13. Raw Reference

| Property         | Zeek                           | Suricata                     | ACID                            |
|---               |---                             |---                           |---                              |
| Raw Field        | Original log reference         | Original log reference       | `raw_ref`                       |
| Data Type        | String / Reference             | String / Reference           | `varchar(512)`                  |
| Required         | No                             | No                           | No                              |
| Exampl           |`zeek://<dataset>/<log>#line-<n>`|`suricata://<dataset>/eve.json#line-<n>`|       --          |
| Missing Behavior | Store NULL                     | Store NULL                   | Store NULL                      |
| Evidence         | Reference to original          | Reference to original        | `raw_ref`                       |
                     Zeek log                         Suricata log

**Normalization Rules:**
- Store a reference to the original raw log record in ACID `raw_ref`.
- The reference may identify the source file, file path, and/or record location.
- Do not treat `raw_ref` as the raw event content itself.
- If the original log reference is unavailable, store `NULL`.
- Keep the reference traceable so analysts can locate the original event during investigation.








### 14. ACID-Generated Fields

#### event_id

| Property        | Value                                                   |
|---              |---                                                      |
| Source          | Generated by ACID Backend                               |
| Raw Field       | Not provided directly by Zeek or Suricata               |
| Generation Rule | `evt_` + first 32 hex chars of SHA-256 over `sensor_id` |
| Responsibility  | Backend                                                 |
| Purpose         | Event identification and idempotency                    |

**Notes:**
- `event_id` is generated by the ACID Backend, not extracted from network telemetry.
- Zeek `uid` remains a source-specific connection identifier.
- Do not map Zeek `uid` to ACID `event_id`.



#### event_version

| Property  | Value                                             |
|---        |---                                                |
| Source    | Generated / assigned by ACID                      |
| Raw Field | Not provided directly by Zeek or Suricata         |
| Data Type | String                                            |
| Example   | `"1.0"`                                           |
| Required  | As defined by the ACID Event Contract             |
| Purpose   | Identifies the version of the ACID Event Contract |

**Versioning Rules:**
- Use `"1.0"` for the initial Event Contract version.
- Additive optional fields remain within the `1.x` version series.
- Breaking changes require a new contract under `contracts/v2/`.






### 15. SSH Event Fields

#### Authentication Attempt

| Property | Value |
|---|---|
| Event Type | `authentication_attempt` |
| `outcome` | Required |
| Allowed Values | `success`, `failure` |
| `service` | `"ssh"` |

**Rules:**
- `outcome` must be either `success` or `failure`.
- `service` must be `"ssh"`.

#### Network Connection

| Property | Value |
|---|---|
| Event Type | `network_connection` |
| `outcome` | `null` |
| `username` | `null` |

**Rules:**
- Set `outcome` to `null`.
- Set `username` to `null`.
- Do not infer an authentication outcome from a network connection event alone.
