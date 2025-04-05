# 🚀 Ultimate Website Reconnaissance & Vulnerability Assessment Tool

![Python Version](https://img.shields.io/badge/python-3.8%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![Security](https://img.shields.io/badge/security-tool-red)

The **Ultimate Website Scanner** is a powerful, all-in-one security assessment tool designed to perform deep reconnaissance and comprehensive vulnerability analysis of web applications and servers.

---

## 🌟 Features

### 🔍 Reconnaissance
- DNS enumeration & IP resolution
- Full port scanning with service detection
- Subdomain discovery
- Cloud infrastructure detection
- WHOIS information lookup

### 🕵️ Web Analysis
- Technology stack fingerprinting (via Wappalyzer)
- SSL/TLS configuration assessment
- CMS detection (WordPress, Joomla, Drupal)
- Header and cookie security analysis

### 📂 Content Discovery
- JavaScript-rendered content spidering
- Form extraction and analysis
- Hidden comments and JavaScript review
- SEO and metadata audits
- Webpage screenshot capturing

### 🛡️ Security Checks
- Vulnerability scanning (Nikto & Nuclei integration)
- CORS misconfiguration detection
- Security header verification
- Sensitive file discovery
- Authentication & session testing
- CSRF, Clickjacking, SQLi, and XSS detection

### 📊 Reporting
- Multiple formats: JSON, HTML, Markdown, Text
- Risk scoring & prioritization
- Executive summary + technical findings

---

## 🛠️ Installation

### ✅ Prerequisites
- Python 3.8+
- Google Chrome / Chromium browser
- Nmap
- *(Optional)* Nikto & Nuclei for advanced scanning

### ⚙️ Setup
```bash
git clone https://github.com/yourusername/ultimate-scanner.git
cd ultimate-scanner
pip install -r requirements.txt
python -m webdriver_manager install
```

---

## 🚦 Usage Examples

### 🔹 Basic Scan
```bash
python webscan.py https://example.com
```

### 🔹 Full Scan (All Ports + Aggressive Checks)
```bash
python webscan.py https://example.com --full --aggressive
```

### 🔹 Save as HTML Report
```bash
python webscan.py https://example.com --output html --save
```

---

## 🧩 Command Line Options

| Option | Description | Default |
|--------|-------------|---------|
| `-h`, `--help` | Show help message | — |
| `-f`, `--full` | Full scan (all ports) | False |
| `-hp`, `--hidden-ports` | Scan hidden ports | False |
| `-a`, `--aggressive` | Aggressive/intrusive checks | False |
| `-o`, `--output` | Output format: `json`, `html`, `markdown`, `text` | json |
| `-s`, `--save` | Save report to file | False |
| `-v`, `--verbose` | Verbose logging | False |
| `-t`, `--threads` | Maximum threads to use | 15 |

---

## ⚙️ Configuration

Customize scanning behavior in the script via the `CONFIG` dictionary:

```python
CONFIG = {
    'timeouts': {
        'requests': 20,
        'selenium': 60,
        'nmap': 1200,
        'subprocess': 900
    },
    'ports': {
        'default': '80,443,8080,8443',
        'hidden': '3000-4000,5000-6000',
        'full': '1-65535'
    },
    'max_threads': 15,
    'rate_limit_delay': 0.1,
    'max_pages': 100,
    'max_depth': 5
}
```

---

## 📝 Sample Report (JSON)
```json
{
  "metadata": {
    "url": "https://example.com",
    "domain": "example.com",
    "timestamp": "2023-12-15T12:00:00Z",
    "execution_time": 125.7,
    "tool_version": "3.1"
  },
  "findings": {
    "network": {
      "ip_addresses": ["93.184.216.34"],
      "dns_records": {
        "A": ["93.184.216.34"],
        "MX": ["10 mail.example.com"]
      },
      "open_ports": {
        "80/tcp": {
          "service": "http",
          "product": "nginx",
          "version": "1.18.0"
        }
      }
    },
    "web": {
      "technologies": {
        "Nginx": {
          "version": "1.18.0",
          "categories": ["web-servers"]
        }
      },
      "security_headers": {
        "X-Frame-Options": "MISSING",
        "Content-Security-Policy": "MISSING"
      }
    }
  },
  "vulnerabilities": [
    {
      "type": "missing_security_header",
      "severity": "medium",
      "description": "Missing X-Frame-Options header",
      "remediation": "Add X-Frame-Options header"
    }
  ]
}
```

---

## 📸 Screenshots

### 🔹 Dashboard View
*Sample HTML dashboard report showing key metrics.*

### 🔹 Vulnerabilities Panel
*Detailed list of identified vulnerabilities with severity and remediation.*

---

## 📜 License

This project is licensed under the MIT License. See the [LICENSE](./LICENSE) file for more details.

---

## ⚠️ Disclaimer

> 🛡️ **Legal Notice**  
> This tool is intended strictly for authorized security testing.  
> - You **must** obtain permission before scanning any system.  
> - Do **not** use this tool for illegal, malicious, or unauthorized purposes.  
> - The authors are not liable for any misuse.  
> - Use it at your own risk.  

By using this tool, you agree to conduct only **legal and ethical** security assessments.
