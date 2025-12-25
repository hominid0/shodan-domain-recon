🔍 Shodan Domain Recon

Passive OSINT tool to enumerate all Shodan-indexed information related to a domain. Designed for bug bounty, responsible disclosure and security research workflows.

✨ Features
🌐 Passive DNS subdomain enumeration using Shodan DNS
🔁 Domain to IP resolution
🔎 Shodan searches using domain-based queries
🧩 Shodan host enumeration including ports, services and metadata
🧾 HTTP headers and basic web metadata extraction
🔐 SSL certificate subject and issuer information
💤 Fully passive reconnaissance, no active scanning
💾 Results automatically saved per analyzed domain

📦 Requirements
🐍 Python 3.9 or higher
🔑 Valid Shodan API Key

🐍 Virtual Environment (recommended)
Create and activate a virtual environment to avoid dependency issues:

python3 -m venv venv
source venv/bin/activate

⚙️ Installation
Clone the repository and install dependencies:

git clone https://github.com/hominid0/shodan-domain-recon.git
cd shodan-domain-recon
pip install -r requirements.txt

🔐 Configuration
Set your Shodan API Key as an environment variable before running the tool.

Linux / macOS:
export SHODAN_API_KEY="YOUR_API_KEY_HERE"

Windows (PowerShell):
setx SHODAN_API_KEY "YOUR_API_KEY_HERE"

Close and reopen the terminal after setting the variable.

🚀 Usage
Run the script providing a target domain:

python shodan_domain_recon.py example.com

📄 Output
All results are automatically saved to a text file:

results/example.com.txt

The output report may include:
📌 Discovered subdomains
🌍 Resolved IP addresses
🔓 Open ports and exposed services
🧠 Product and version fingerprints
🌐 HTTP titles and server headers
🔐 SSL certificate metadata
🏢 ASN, ISP and organization information

🗂️ Project Structure
shodan-domain-recon/
├── shodan_domain_recon.py
├── requirements.txt
├── README.md
├── LICENSE
├── .gitignore
└── results/ (created automatically)

❗ Common Errors
If you see the error "ModuleNotFoundError: No module named 'shodan'", activate the virtual environment and install dependencies again:

source venv/bin/activate
pip install -r requirements.txt

⚠️ Legal Disclaimer
This tool is intended for authorized security testing only. Use it exclusively on assets you own or have explicit permission to test. The author assumes no responsibility for misuse.

🤝 Contributions
Pull requests, improvements and suggestions are welcome. If you find this tool useful, consider giving the repository a star.
