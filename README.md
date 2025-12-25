# Shodan Domain Recon

Passive OSINT tool to enumerate all Shodan-indexed information related to a domain.

Designed for **bug bounty**, **responsible disclosure**, and **security research** workflows.

---

## ✨ Features

- Passive DNS subdomain enumeration (Shodan DNS)
- Domain → IP resolution
- Shodan search using domain-based queries
- Shodan host enumeration (ports, services, metadata)
- Fully passive (no active scanning)
- Results saved per domain

---

## 📦 Requirements

- Python 3.9+
- Shodan API Key

Install dependencies:

```bash
pip install -r requirements.txt
