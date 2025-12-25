# 🔍 Shodan Domain Recon

Passive OSINT tool to enumerate **all Shodan-indexed information** related to a domain.

Designed for **bug bounty**, **responsible disclosure**, and **security research workflows**.

---

## ✨ Features

- 🌐 Passive DNS subdomain enumeration (Shodan DNS)
- 🔁 Domain → IP resolution
- 🔎 Shodan search using domain-based queries
- 🧩 Shodan host enumeration (ports, services, metadata)
- 🧾 HTTP headers and SSL certificate extraction
- 💤 Fully passive (no active scanning)
- 💾 Results saved per domain

---

## 📦 Requirements

- 🐍 Python **3.9+**
- 🔑 Shodan API Key

Install dependencies:

```bash
pip install -r requirements.txt
```

---

## ⚙️ Installation

### 1️⃣ Clone the repository

```bash
git clone https://github.com/hominid0/shodan-domain-recon.git
cd shodan-domain-recon
```

### 2️⃣ Install dependencies

```bash
pip install -r requirements.txt
```

---

## 🔐 Configuration (IMPORTANT)

You must set your **Shodan API Key** as an environment variable.

### 🐧 Linux / macOS

```bash
export SHODAN_API_KEY="YOUR_API_KEY_HERE"
```

### 🪟 Windows (PowerShell)

```powershell
setx SHODAN_API_KEY "YOUR_API_KEY_HERE"
```

⚠️ Close and reopen the terminal after setting the variable.

---

## 🚀 Usage

Run the script providing a domain as argument:

```bash
python shodan_domain_recon.py example.com
```

---

## 📄 Output

Results are automatically saved to:

```
results/example.com.txt
```

The report may include:

- 📌 Discovered subdomains
- 🌍 IP addresses
- 🔓 Open ports and exposed services
- 🧠 Product and version fingerprints
- 🌐 HTTP titles and server headers
- 🔐 SSL certificate metadata
- 🏢 ASN / ISP / Organization info

---

## 🗂️ Project structure

```
shodan-domain-recon/
├── shodan_domain_recon.py
├── requirements.txt
├── README.md
├── LICENSE
├── .gitignore
└── results/        # created automatically
```

---

## ⚠️ Legal disclaimer

This tool is intended for **authorized security testing only**.

Use it **only on assets you own or have explicit permission to test**.  
The author assumes **no responsibility for misuse**.

---

## 🤝 Contributions

Pull requests, improvements and suggestions are welcome.

If you find this tool useful ⭐ the repository!
