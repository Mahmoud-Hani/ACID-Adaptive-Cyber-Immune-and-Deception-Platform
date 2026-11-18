# Benign Traffic Plan (False Positive Validation)

## Objective
To generate normal/benign traffic inside the isolated lab to validate that the detection engines do NOT produce false positives.

## Validation Matrix
| Profile | Command (from Kali) | Target | Expected Log | Expected Detection |
| :--- | :--- | :--- | :--- | :--- |
| **Normal SSH** | `ssh lab-user@10.10.10.30` | Victim | `ssh.log` (auth_success=true) | **None** |
| **Normal Web** | `curl http://10.10.10.30` | Victim | `conn.log` (HTTP) | **None** |
| **Normal DNS** | `nslookup google.com` | DNS Server | `dns.log` | **None** |

*Note: These benign profiles will be executed by Red 2 in Week 2 to ensure the Blue Team's detectors do not flag normal behavior.*