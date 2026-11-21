# CTI Provider Boundary & Timeout Policy

## 1. Primary Demo Path (Offline-First)
- The default provider is the deterministic local fixture loader (`offline-fixture`).
- No external Internet access or live API keys are required for the Term 1 Demo.

## 2. Timeout & Failure Handling
- Recommended Backend HTTP client timeout: **2000ms (2 seconds)**.
- On timeout, HTTP 5xx, or simulated offline error (`stale: true`, `error != null`), the Backend must catch the exception, record the error status on the Incident, and proceed without blocking alert generation.

## 3. Future Live Provider Adapter (Optional)
- Live providers (e.g., AbuseIPDB, AlienVault OTX) must implement the exact same `EnrichResponse` schema defined in `ai/cti/enrichment-contract.md`.