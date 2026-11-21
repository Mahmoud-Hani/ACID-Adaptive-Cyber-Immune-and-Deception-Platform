# CTI Enrichment Service Contract (`POST /enrich`)

## 1. Endpoint Specification

- **Method:** `POST`
- **Path:** `/enrich`
- **Content-Type:** `application/json`
- **Behavior:** Non-blocking enrichment. Failure or `no-hit` must never prevent Incident creation.

## 2. Request Schema

```json
{
  "indicator": "10.10.10.20",
  "indicator_type": "ipv4",
  "incident_id": "INC-2026-001"
}
```

## 3.Response Schema

# Case A: Known Threat Match (Hit) — 200 OK

```json
{
  "indicator": "10.10.10.20",
  "match": true,
  "source": "offline-fixture",
  "tags": ["scanner", "suspicious"],
  "confidence": 0.85,
  "fetched_at": "2026-11-20T12:00:00Z",
  "stale": false,
  "error": null
}
```

# Case B: Unknown Indicator (No-Hit) — 200 OK

```json
{
  "indicator": "8.8.8.8",
  "match": false,
  "source": "offline-fixture",
  "tags": [],
  "confidence": 0.0,
  "fetched_at": "2026-11-20T12:00:00Z",
  "stale": false,
  "error": null
}
```

# Case C: Provider Offline / Simulated Error — 200 OK

```json
{
  "indicator": "192.0.2.99",
  "match": false,
  "source": "offline-fixture",
  "tags": [],
  "confidence": 0.0,
  "fetched_at": "2026-11-20T12:00:00Z",
  "stale": true,
  "error": "CTI_PROVIDER_OFFLINE: Upstream threat feed unreachable"
}
```
# 4. Supported Test Indicators (Offline Fixtures)
10.10.10.20 -> Returns Hit (ai/fixtures/cti-hit.json)

8.8.8.8 -> Returns No-Hit (ai/fixtures/cti-no-hit.json)

192.0.2.99 -> Returns Offline/Error (ai/fixtures/cti-offline.json)

Any other unknown indicator -> Returns dynamic No-Hit (match: false)