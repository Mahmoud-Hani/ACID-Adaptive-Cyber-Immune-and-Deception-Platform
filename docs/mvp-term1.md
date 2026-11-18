# ACID Term 1 MVP (Minimum Viable Product)

## 1. Overview & Objective
The Term 1 MVP is a complete, working defensive pipeline that proves ACID can detect, analyze, and visualize security incidents in an isolated lab environment. It is not just a concept; it is an executable end-to-end demo.

## 2. In-Scope (What we ARE building)
The pipeline will process network traffic and output incidents based on two specific attack scenarios:
1. **Port Scan (MITRE T1046)**
2. **SSH Brute Force (MITRE T1110.001)**

### Core Components:
- **Isolated Lab:** VirtualBox Host-Only network (`10.10.10.0/24`) with Kali (Attacker), Debian (Victim), and a Sensor.
- **Telemetry:** Zeek and Suricata generating `conn.log` and `ssh.log`.
- **Parsing & Normalization:** Translating raw logs into a unified `Event v1` JSON format.
- **Detection Engine:** Two behavior-based detectors (Port Scan threshold, SSH Failed Auth threshold).
- **Backend (ASP.NET Core):** Ingestion, Correlation (grouping events into Incidents), and CTI Enrichment.
- **Dashboard (Data-Driven UI):** A frontend that dynamically reads the `Incident` JSON to display the timeline, evidence, MITRE mapping, and CTI context.

## 3. Out-of-Scope (What is DEFERRED to Term 2)
To ensure Term 1 is delivered successfully, the following features are strictly OUT of scope:
- Machine Learning (ML) / AI Anomaly Detection.
- Honeypot / Cowrie SSH Deception.
- Cyber Immune Memory (Historical incident matching).
- Automated Response / Containment.

## 4. The Demo Story (What the committee will see)
*Total Demo Time: 3 Minutes*
1. **The Setup:** Show the isolated lab topology (Kali, Debian, Sensor).
2. **Attack 1 (Port Scan):** Trigger `scan_01` from Kali. Show Zeek logs. Show the resulting Incident on the Dashboard (T1046 + Evidence + CTI).
3. **Attack 2 (SSH Brute Force):** Trigger `scan_02` from Kali. Show Zeek `ssh.log`. Show the resulting Incident on the Dashboard (T1110.001 + Evidence + CTI).
4. **The Context:** Briefly show how the UI is built to support Term 2 features (ML, Honeypot) without changing the code.

## 5. Success Metrics (Definition of Done)
- [ ] The system detects exactly **one** Incident for Port Scan.
- [ ] The system detects exactly **one** Incident for SSH Brute Force.
- [ ] Normal traffic (Benign) produces **zero** False Positives.
- [ ] The replay script runs successfully **5/5 times** from a clean clone.