# ACID — Adaptive Cyber Immune and Deception Platform

ACID is a defensive network intrusion detection platform developed as a graduation project.

The platform analyzes network telemetry collected from Zeek and Suricata, normalizes raw sensor logs into unified security events, detects suspicious behaviors such as port scanning, correlates detections into incidents, maps them to MITRE ATT&CK techniques, enriches them with Cyber Threat Intelligence, and visualizes the resulting security insights through a centralized dashboard.

The system is designed around a modular repository structure where Backend, Blue Team, Red Team, AI, Dashboard, Lab, and Testing components can be developed independently and integrated through versioned contracts, Pull Requests, automated checks, and documented handoffs.

The Term 1 critical path is:

```text
Red Team Traffic
→ Zeek / Suricata
→ Parser and Event Normalization
→ Backend Ingestion
→ Port Scan Detection
→ Incident Correlation
→ MITRE ATT&CK T1046
→ CTI Enrichment
→ Dashboard
→ End-to-End Testing
