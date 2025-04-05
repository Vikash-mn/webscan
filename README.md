# 🛡️ ULTIMATE Website Reconnaissance & Vulnerability Assessment Tool

![Python Version](https://img.shields.io/badge/python-3.8%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)

A powerful security scanner that performs deep reconnaissance and vulnerability assessment of web applications.

---

## 📚 Table of Contents

- [Features](#features)
- [Installation](#installation)
- [Usage](#usage)
- [Command Line Options](#command-line-options)
- [Sample Output](#sample-output)
- [Configuration](#configuration)
- [Troubleshooting](#troubleshooting)
- [Limitations](#limitations)
- [Legal Disclaimer](#legal-disclaimer)
- [License](#license)
- [Contributing](#contributing)

---

## 🚀 Features

### 🔍 Network Layer Scanning
- DNS enumeration and reverse lookups
- Full port scanning with service detection
- Hidden service discovery
- SSL/TLS configuration analysis

### 🌐 Web Application Analysis
- Technology stack fingerprinting
- CMS detection
- Content spidering (including JS-rendered content)
- Form extraction and analysis
- Comment and metadata extraction

### 🔐 Security Assessment
- Vulnerability scanning (Nikto, Nuclei integration)
- Security headers analysis
- CORS misconfiguration detection
- Common web vulnerabilities (XSS, SQLi, IDOR, etc.)
- Authentication mechanism testing

### 📊 Reporting
- Multiple output formats (JSON, HTML, Markdown)
- Risk assessment scoring
- Screenshot capture
- Executive summary generation

---

## ⚙️ Installation

### 1. Prerequisites
- Python 3.8+
- Chrome/Chromium browser (for Selenium)
- Nmap
- *(Optional)* Nikto and Nuclei for enhanced vulnerability scanning

### 2. Install Python Dependencies

```bash
git clone https://github.com/yourusername/ultimate-scanner.git
cd ultimate-scanner
pip install -r requirements.txt
3. Install ChromeDriver
Download from: https://chromedriver.chromium.org/

Ensure it is in your system PATH or set its location in config.py.

🧪 Usage
Basic Scan:
bash
Copy
Edit
python ultimate_scanner.py https://example.com
Full Comprehensive Scan:
bash
Copy
Edit
python ultimate_scanner.py https://example.com -f -a
Save Results to HTML Report:
bash
Copy
Edit
python ultimate_scanner.py https://example.com -o html -s
Render JavaScript-heavy Sites (with Headless Browser):
bash
Copy
Edit
python ultimate_scanner.py https://example.com --render-js
🛠️ Command Line Options
Option	Description
-f, --full	Perform full scan (all ports)
-hp, --hidden-ports	Scan for hidden/less-common web ports
-a, --aggressive	Aggressive scanning (more intrusive checks)
-o, --output	Output format: json, html, markdown, text
-s, --save	Save results to file
-v, --verbose	Verbose output
--render-js	Use browser automation to render JS content
📂 Sample Output
<pre> [+] Scanning https://example.com [+] Open Ports: 80 (HTTP), 443 (HTTPS) [+] CMS Detected: WordPress [!] X-Frame-Options header missing [!] SQL Injection vulnerability detected on /login.php </pre>
⚙️ Configuration
You can edit the CONFIG dictionary in config.py:

python
Copy
Edit
CONFIG = {
    "timeout": 10,
    "port_range": "1-65535",
    "output_dir": "./reports/",
    "wordlist_path": "./wordlists/common.txt",
    "chromedriver_path": "/usr/local/bin/chromedriver"
}
🧩 Troubleshooting
ChromeDriver not found:
Make sure it’s installed and available in your PATH or configured in config.py.

Permission denied on low ports:
Use elevated privileges or scan ports above 1024.

Scan blocked or rate-limited:
Reduce aggressiveness or implement rate limiting via config.py.

⚠️ Limitations
Requires authorization to scan targets (see disclaimer).

Some features rely on external tools (Nikto, Nuclei).

Aggressive scanning may trigger IDS/WAF/firewalls.

JavaScript-heavy sites require more resources to analyze.

⚖️ Legal Disclaimer
⚠️ DISCLAIMER
This tool is intended only for educational purposes and authorized security testing.
Unauthorized scanning of systems you do not own or have explicit permission to test is illegal and may lead to criminal prosecution.

📄 License
This project is licensed under the MIT License.

🤝 Contributing
Contributions are welcome!

Fork the repository and create your branch

Add features or fix bugs

Submit a pull request with a detailed description

Ensure your code follows the project style


