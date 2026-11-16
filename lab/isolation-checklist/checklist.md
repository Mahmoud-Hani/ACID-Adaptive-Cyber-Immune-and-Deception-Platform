# ACID Lab Isolation Checklist

## Task Information

- Task: W1-R1-03
- Owner: Red Team / Red 1
- Network: VirtualBox Host-Only Ethernet Adapter
- Network CIDR: 10.10.10.0/24
- Check date: 2026-11-16
- Scope: Authorized lab validation only
- Week 1 attack execution: Not performed

## IP Addresses

- Gateway: 10.10.10.1
- Sensor: 10.10.10.10
- Attacker / Kali: 10.10.10.20
- Victim / Debian: 10.10.10.30

## Isolation Checks

### Check 1: Kali to Victim

- Command: ping 10.10.10.30
- Expected: Victim is reachable inside the isolated lab
- Observed: Ping succeeded
- Status: PASS

### Check 2: Kali to Internet

- Command: ping 8.8.8.8
- Expected: Internet target is unreachable
- Observed: Ping failed
- Status: PASS

## Lab Preparation

- SSH installed on Debian: Prepared
- Nginx installed on Debian: Prepared
- Sensor at 10.10.10.10: Pending
- Zeek and Suricata validation: Pending until Week 2

## Safety Rules

1. Keep the lab on VirtualBox Host-Only networking.
2. Do not bridge the lab to a public or physical network.
3. Do not run nmap, Hydra, or other attack commands during Week 1.
4. Do not commit passwords, VM credentials, or sensitive captures to Git.
5. Repeat the isolation check before starting Week 2.

## Week 2 Requirements

- [ ] Recheck Host-Only adapter mode.
- [ ] Record routes and network interfaces.
- [ ] Configure the Sensor at 10.10.10.10.
- [ ] Confirm Zeek and Suricata log locations with Blue Team.
- [ ] Get approval before running scan_01 and scan_02.
