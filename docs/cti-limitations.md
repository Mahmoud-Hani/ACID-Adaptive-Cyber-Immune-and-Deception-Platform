# CTI Enrichment Limitations

1. **Context Only, Not Proof:** CTI enrichment adds external reputation context to an existing Detection or Incident; it does not independently prove an attack occurred.
2. **No-Hit ≠ Benign:** A `match: false` (`no-hit`) response means the indicator is absent from the CTI feed, **not** that the IP is safe or benign.
3. **Port Scans & CVEs:** A Port Scan (`T1046`) or CTI tag must never be linked to a specific CVE without verified asset inventory and vulnerability evidence.
4. **Non-Blocking Pipeline:** CTI provider downtime, timeouts, or offline errors must never block Incident creation.
5. **Offline Demo Guarantee:** Primary enrichment relies on deterministic local fixtures (`ai/fixtures/`) so the Demo runs reliably without Internet access or API keys.
