# Ultimate Website Reconnaissance & Vulnerability Assessment Tool

![Security Scanner](https://img.shields.io/badge/Type-Security%20Scanner-blue)
![Python](https://img.shields.io/badge/Python-3.8%2B-green)
[![License](https://img.shields.io/badge/License-MIT-red)](LICENSE)

The ultimate all-in-one website reconnaissance and vulnerability assessment tool with comprehensive scanning capabilities.

## Features

- **Network Layer Scanning**:
  - DNS enumeration and IP reconnaissance
  - Full port scanning with service detection
  - Hidden service discovery
  - Cloud asset detection

- **Web Layer Analysis**:
  - Technology stack fingerprinting
  - SSL/TLS configuration assessment
  - CMS detection
  - Header analysis

- **Content Discovery**:
  - Advanced spidering (including JS-rendered content)
  - Form extraction
  - Comment/JS analysis
  - SEO assessment

- **Security Checks**:
  - Vulnerability scanning (Nikto, Nuclei)
  - CORS misconfiguration detection
  - Security header verification
  - Sensitive file discovery
  - Authentication mechanism testing

- **Reporting**:
  - JSON, HTML, Markdown, and text output formats
  - Risk assessment scoring
  - Relationship analysis between findings

## Installation

1. **Prerequisites**:
   - Python 3.8+
   - Chrome/Chromium (for Selenium)
   - Nmap
   - Nikto (optional)
   - Nuclei (optional)

2. **Install dependencies**:
   ```bash
   pip install -r requirements.txt
Install web drivers (for Selenium):

bash
Copy
python -m webdriver_manager install
Usage
bash
Copy
python ultimate_scanner.py [URL] [OPTIONS]
Basic Scan
bash
Copy
python ultimate_scanner.py https://example.com
Full Scan (All Ports + Aggressive Checks)
bash
Copy
python ultimate_scanner.py https://example.com -f -a
Save Results to File
bash
Copy
python ultimate_scanner.py https://example.com -o html -s
Options
Copy
  -h, --help            show help message
  -f, --full            full scan (all ports)
  -hp, --hidden-ports   scan for hidden web ports
  -a, --aggressive      aggressive scanning (intrusive checks)
  -o {json,html,markdown,text}, --output {json,html,markdown,text}
                        output format (default: json)
  -s, --save            save results to file
  -v, --verbose         verbose output
  -t THREADS, --threads THREADS
                        maximum threads to use (default: 15)
Configuration
The tool can be configured by modifying the CONFIG dictionary in the script:

python
Copy
CONFIG = {
    'timeouts': {
        'requests': 20,          # Request timeout in seconds
        'selenium': 60,          # Selenium timeout
        'nmap': 1200,            # Nmap scan timeout
        'subprocess': 900        # Subprocess timeout
    },
    'max_threads': 15,          # Concurrent threads
    'rate_limit_delay': 0.1     # Delay between requests
}
Sample Output Structure
json
Copy
{
  "metadata": {
    "url": "https://example.com",
    "domain": "example.com",
    "timestamp": "2023-12-15T12:00:00Z",
    "tool_version": "3.1"
  },
  "findings": {
    "network": {
      "ip_dns": {...},
      "open_ports": {...},
      "dns_enumeration": {...}
    },
    "web": {
      "technologies": {...},
      "ssl_tls": {...},
      "headers": {...}
    },
    "security": {
      "vulnerabilities": {...},
      "security_headers": {...}
    }
  }
}
Screenshots
Sample Report

License
MIT License - See LICENSE for details.

Disclaimer
This tool is for authorized security testing and educational purposes only. The developers assume no liability and are not responsible for any misuse or damage caused by this program.

Copy

## Additional Recommended Files

### .gitignore
Byte-compiled / optimized / DLL files
pycache/
*.py[cod]
*$py.class

Virtual environment
venv/
ENV/

IDE specific files
.idea/
.vscode/
*.swp
*.swo

Output files
scan_results/
screenshots/

Logs and databases
*.log
*.sqlite

System files
.DS_Store
Thumbs.db

Copy

### LICENSE
```text
MIT License

Copyright (c) [year] [fullname]

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
This complete package provides:

All necessary dependencies

Comprehensive documentation

Clear usage instructions

Configuration guidance

License and disclaimer

Proper project structure with .gitignore
