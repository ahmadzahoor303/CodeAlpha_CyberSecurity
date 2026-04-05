# CodeAlpha Cybersecurity Internship — Tasks

**Intern Name:** Muhammad Ahmad  
**ID:** CA/DF1/43736
**Internship:** CodeAlpha Cybersecurity  
**Tasks Completed:** Task 1, Task 2, Task 3

---

## Task 1 — Basic Network Sniffer

### Description
A Python program that captures live network traffic packets and displays useful information such as source/destination IPs, protocols, ports, and payloads.

### Features
- Captures real-time IP packets using Scapy
- Shows Source IP, Destination IP, Protocol, Port numbers
- Displays packet payload (decoded text or hex)
- Saves all captured packets to a log file (`captured_packets.log`)
- Works on Windows, Linux, and Mac

### How To Run
```bash
# Install dependency
pip install scapy

# Windows — Run CMD as Administrator, then:
set PYTHONIOENCODING=utf-8
python task1_network_sniffer.py

# Linux / Mac
sudo python3 task1_network_sniffer.py
```

### Libraries Used
- `scapy` — packet capturing and analysis
- `datetime` — timestamping packets
- `os` — system-level operations

### Sample Output
```
────────────────────────────────────────
  Packet #001  [2026-04-05 20:05:08]
  From   : 172.64.148.235
  To     : 192.168.100.183
  Proto  : TCP (flags=A)
  Ports  : 443 → 58219
```

---
<img width="947" height="202" alt="image" src="https://github.com/user-attachments/assets/d21bb34d-5fa9-4733-93c2-94e40fc5301a" />


## Task 2 — Phishing Awareness Training

### Description
An interactive web-based training module that educates users about phishing attacks, social engineering tactics, and how to stay safe online.

### Features
- 5 interactive learning modules
- Real phishing email simulator (click to reveal if phishing or safe)
- Social engineering tactics explained
- Best practices tips grid
- 6-question interactive quiz with instant feedback and scoring
- No installation required — runs in any browser

### How To Run
```
Simply double-click task2_phishing_awareness.html
Opens in your browser instantly — no setup needed!
```

### Topics Covered
- What is Phishing? (Email, Spear, Smishing, Vishing, Whaling)
- How to spot phishing emails (red flags)
- Social engineering tactics (Urgency, Fear, Authority, etc.)
- Best practices to stay safe
- Interactive knowledge quiz

---

## Task 3 — Secure Coding Review

### Description
A Python-based static code analysis tool that scans Python source files for common security vulnerabilities and provides detailed remediation recommendations.

### Features
- Scans single files or entire project folders
- Detects 10 types of vulnerabilities
- Color-coded severity levels (HIGH / MEDIUM / LOW)
- Provides fix recommendations for each issue
- Saves report to `security_report.txt`

### Vulnerabilities Detected
| ID | Severity | Vulnerability |
|----|----------|--------------|
| SQL-01 | HIGH | SQL Injection |
| SEC-01 | HIGH | Hardcoded Passwords/Secrets |
| INJ-01 | HIGH | Use of eval() / exec() |
| INJ-02 | HIGH | Shell Injection (subprocess) |
| CRY-02 | HIGH | Weak Hashing (MD5/SHA1) |
| DSR-01 | HIGH | Unsafe Pickle Deserialization |
| TLS-01 | HIGH | SSL Verification Disabled |
| CRY-01 | MEDIUM | Insecure Random Number Generator |
| CFG-01 | MEDIUM | Debug Mode Enabled |
| ERR-01 | LOW | Broad Exception Suppression |

### How To Run
```bash
# Scan a single file
python task3_secure_coding_review.py sample_vulnerable_app.py

# Scan an entire folder
python task3_secure_coding_review.py ./my_project/
```

### Sample Output
```
Issues found : 10
HIGH   : 7
MEDIUM : 2
LOW    : 1

Issue #1  [HIGH]  SEC-01
Title : Hardcoded password / secret detected
File  : sample_vulnerable_app.py (line 16)
Code  : db_password = "supersecret123"
Fix   : Use environment variables instead
```
<img width="1102" height="845" alt="image" src="https://github.com/user-attachments/assets/eef7c2bc-b698-45b9-890f-8c767bb291f1" />

### Libraries Used
- `re` — regex pattern matching
- `pathlib` — file system navigation
- `sys`, `os` — system operations

---

## Tech Stack
- Python 3.x
- Scapy
- HTML / CSS / JavaScript (Task 2)

## Repository Structure
```
CodeAlpha_Tasks/
├── task1_network_sniffer.py       # Network Sniffer
├── task2_phishing_awareness.html  # Phishing Training Module
├── task3_secure_coding_review.py  # Secure Code Scanner
├── sample_vulnerable_app.py       # Demo file for Task 3
├── security_report.txt            # Sample scan report
└── README.md                      # This file
└── captured_packets.log
```

## 🔗 Connect
- LinkedIn: [Your LinkedIn Profile]
- GitHub: [Your GitHub Profile]
