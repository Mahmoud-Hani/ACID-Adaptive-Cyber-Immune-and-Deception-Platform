# Demo Operator Checklist

## 1. Pre-Flight Checks (Before the Committee arrives)
- [ ] Ensure VirtualBox Host-Only network is up (`10.10.10.1`).
- [ ] Boot Victim (Debian) `10.10.10.30` and verify Nginx + SSH are running.
- [ ] Boot Attacker (Kali) `10.10.10.20`.
- [ ] Boot Sensor (Zeek/Suricata) `10.10.10.10`.

## 2. Live Execution (Port Scan Scenario)
- [ ] Run Nmap from Kali to Victim (`scan_01`).
- [ ] Show Zeek `conn.log` to prove telemetry capture.
- [ ] Show the parsed Event.
- [ ] Show the generated Incident on the Dashboard (T1046 + Evidence + CTI).

## 3. Live Execution (SSH Brute Force Scenario)
- [ ] Run Hydra from Kali to Victim (`scan_02`).
- [ ] Show Zeek `ssh.log` to prove telemetry capture.
- [ ] Show the parsed Event.
- [ ] Show the generated Incident on the Dashboard (T1110.001 + Evidence + CTI).

## 4. Emergency Fallback (If live fails)
- [ ] If the live attack fails, immediately play the pre-recorded video.
- [ ] Display the static screenshots of the seeded Incidents on the Dashboard.