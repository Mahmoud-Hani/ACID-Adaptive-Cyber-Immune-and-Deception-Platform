# ACID — Adaptive Cyber Immune and Deception Platform

> **ACID** is a Next-Generation Defensive Cybersecurity Platform designed to monitor network activity, detect suspicious behavior, correlate security incidents, and provide explainable incident analysis. It integrates network telemetry, behavior-based detection, Threat Intelligence (CTI), MITRE ATT&CK mapping, and deception mechanisms to improve threat visibility.

---

## 📖 1. Project Overview
ACID is developed as a graduation project. Traditional security tools produce large volumes of isolated alerts. ACID bridges this gap by connecting network telemetry collection, event normalization, detection logic, incident correlation, threat intelligence enrichment, and analyst-friendly visualization into one structured defensive platform.

The system operates within an **isolated, authorized laboratory environment** and is designed with an extensible architecture to support future AI/ML and deception capabilities.

---

## 🎯 2. Core Capabilities (Term 1 MVP)
In the first term, the ACID platform delivers a complete, working defensive pipeline focusing on two primary attack scenarios:

1. **Port Scanning (MITRE ATT&CK T1046):** Detects multiple connection attempts across various ports within a time window.
2. **SSH Brute Force (MITRE ATT&CK T1110.001):** Detects repeated failed authentication attempts on SSH services.

### 🔄 The ACID Pipeline
1. **Attack Simulation (Red Team):** Authorized traffic generation (Nmap, Hydra) inside an isolated VirtualBox Lab.
2. **Telemetry (Sensors):** Zeek and Suricata capture raw network logs (`conn.log`, `ssh.log`).
3. **Normalization (Blue Team):** Parsers convert raw logs into a unified `Event v1` JSON schema.
4. **Ingestion & Correlation (Backend):** ASP.NET Core APIs ingest events, group them into Incidents, and apply a risk score.
5. **Intelligence (AI Team):** Incidents are mapped to MITRE ATT&CK and enriched with Cyber Threat Intelligence (CTI).
6. **Visualization (Dashboard):** A dynamic, data-driven React dashboard allows analysts to investigate incidents, view evidence timelines, and understand the "Why".

---

## 🚀 3. Future Vision (Term 2 — Adaptive Intelligence)
The architecture is built to be **future-proof**. Term 2 will introduce:
- **AI/ML-Based Detection:** Anomaly detection and behavioral analysis for unknown threats.
- **Honeypot & Deception:** Integration of Cowrie SSH traps to deceive attackers and gather intelligence.
- **Cyber Immune Memory:** A historical database to match current incidents with past behaviors for faster response.
- **Advanced Detection Engines:** Expanding beyond Port Scan and SSH to multi-event behavioral patterns.

---

## 🏗️ 4. Repository Structure & Modularity
The project follows a strict modular architecture. Each team works on dedicated branches and integrates via versioned JSON contracts.

- `backend/` — ASP.NET Core API, Database, Incident Correlation, Risk Scoring.
- `blue-team/` — Zeek/Suricata field mapping, Parsers, Detection Engine logic.
- `red-team/` — Lab topology, Attack scenarios (Nmap, Hydra), Benign traffic generation.
- `ai/` — CTI enrichment (FastAPI), MITRE ATT&CK mapping, Contract testing.
- `dashboard/` — Data-driven UI (React) for analyst investigation.
- `contracts/` — Versioned JSON schemas (`Event`, `Detection`, `Incident`).
- `lab/` — Network topology, IP plans, Isolation checklists.
- `docs/` — Architecture, MVP scope, ADRs (Architecture Decision Records).

---

## 🛠️ 5. Technology Stack
- **Network Telemetry:** Zeek, Suricata, PCAP (Offline Replay).
- **Backend:** ASP.NET Core (C#), Entity Framework Core.
- **Frontend Dashboard:** React, Tailwind CSS (Data-driven design).
- **AI & CTI:** Python (FastAPI), Offline Fixtures.
- **Lab Environment:** VirtualBox (Host-Only Network `10.10.10.0/24`), Kali Linux, Debian 12.

---

## 👥 6. Team Roles
The project is executed by a 7-member team:
- **Red 1 & Red 2:** Lab infrastructure, PCAP generation, Benign traffic, UI Design.
- **Blue 1 & Blue 2:** Telemetry parsing, Detection engines, ATT&CK evidence, Architecture.
- **AI 1 & AI 2:** CTI enrichment, Contract testing, CI/CD, Future ML design.
- **Backend:** API development, Database, Incident correlation.

---

## ⚠️ 7. Disclaimer
**All cybersecurity activities, attack simulations (Port Scanning, SSH Brute Forcing), and traffic generations in this repository are performed strictly within an isolated, authorized, and controlled laboratory environment.** 
No external networks, public IP addresses, or unauthorized devices are targeted. The platform is built purely for defensive research and educational purposes.
