# CodeAlpha Cybersecurity Internship

Complete implementations of all four CodeAlpha cybersecurity internship tasks, tested on **Kali Linux**.

---

## Quick Setup (Kali Linux)

```bash
# Install the one dependency all tasks share
sudo apt update
sudo apt install python3-pip -y
pip install scapy
```

---
## Task 4 — Network Intrusion Detection System

**File:** `task4_nids/nids.py`

```bash
# List interfaces
sudo python3 task4_nids/nids.py --list

# Run NIDS on eth0
sudo python3 task4_nids/nids.py -i eth0

# Run with logging and auto-block on CRITICAL
sudo python3 task4_nids/nids.py -i eth0 -l /var/log/nids.log \
    -a "iptables -I INPUT -s {src} -j DROP"
```

**Features:** Port scan detection, brute-force detection, flood/DoS, ARP spoofing, web attack signatures, JSON report on exit.

---

## GitHub Upload

```bash
git init
git add .
git commit -m "CodeAlpha Cybersecurity Internship"
git remote add origin https://github.com/vpawankumar2025-crypto/CodeAlpha_Network-Intrusion-Detection-System 
git push -u origin main
```

---

*CodeAlpha Cybersecurity Internship | Pawan Kumar V | 2026*
