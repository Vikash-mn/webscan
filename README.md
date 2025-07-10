# ULTIMATE Website Reconnaissance & Vulnerability Assessment Tool

The ULTIMATE Website Scanner is a comprehensive security assessment tool designed for penetration testers, security researchers, and system administrators. This all-in-one solution combines network scanning, web technology detection, vulnerability assessment, and reporting capabilities into a single powerful Python tool.

## Key Capabilities

The tool performs complete website reconnaissance including:

1. **Network Discovery**  
   - Full port scanning with Nmap integration
   - DNS enumeration (A, AAAA, MX, TXT records)
   - SSL/TLS certificate analysis
   - Cloud infrastructure detection (AWS, Azure, GCP)

2. **Technology Fingerprinting**  
   - Automatic detection of 300+ technologies
   - CMS identification (WordPress, Drupal, Joomla)
   - Framework detection (Laravel, Django, Rails)
   - JavaScript library analysis (React, Angular, Vue)

3. **Security Assessment**  
   - OWASP Top 10 vulnerability scanning
   - Automated checks with Nikto and Nuclei
   - Authentication mechanism testing
   - CSRF/XSS/SQL injection detection

4. **Content Analysis**  
   - Full-site spidering with JavaScript rendering
   - Form extraction and analysis
   - Comment/metadata mining
   - SEO configuration checks

5. **Reporting**  
   - Multiple output formats (JSON, HTML, Markdown)
   - Screenshot capture of all pages
   - Executive summaries and technical details

## Installation Guide

### Prerequisites

```bash
# On Ubuntu/Debian:
sudo apt update && sudo apt install -y \
    python3.9 \
    chromium-browser \
    nmap \
    nikto \
    nuclei \
    sslyze
Python Setup
bash
# Clone repository
git clone https://github.com/yourrepo/webscanner.git
cd webscanner

# Install dependencies
pip install -r requirements.txt

# Set up wordlists
mkdir -p /usr/share/wordlists
wget https://github.com/danielmiessler/SecLists/archive/master.zip
unzip master.zip -d /usr/share/wordlists/
Usage Examples
Basic Scan (Non-intrusive)
bash
python webscan.py https://example.com
Comprehensive Security Audit
bash
python webscan.py https://example.com \
    -f \          # Full port scan
    -a \          # Aggressive checks
    -t 20 \       # 20 threads
    -o html \     # HTML report
    -s \          # Save to file
    -v            # Verbose output
Targeted Technology Analysis
bash
python webscan.py https://example.com \
    --skip-network \    # Skip port scanning
    --skip-security     # Skip vulnerability checks
Complete Command Reference
Option	Description	Default
url	Target URL to scan	Required
-f, --full	Scan all 65535 ports	False
-hp, --hidden-ports	Scan uncommon web ports	False
-a, --aggressive	Run intrusive checks	False
-o FORMAT	Output format (json/html/md/txt)	json
-s, --save	Save results to file	False
-v, --verbose	Show detailed output	False
-t NUM, --threads NUM	Maximum threads to use	15
--rate-limit SEC	Delay between requests (seconds)	0.1
--random-delay	Add random delay to requests	False
--skip-network	Skip network scanning	False
--skip-tech	Skip technology detection	False
--skip-security	Skip vulnerability scanning	False
--no-selenium	Disable browser rendering	False
Configuration Options
The tool can be customized by editing the CONFIG dictionary in webscan.py:

python
CONFIG = {
    # Timeout settings (seconds)
    'timeouts': {
        'requests': 20,       # HTTP requests
        'selenium': 60,       # Browser operations
        'nmap': 1200,         # Port scanning
        'subprocess': 900     # External tools
    },
    
    # Wordlist paths
    'wordlists': {
        'dirs': '/usr/share/wordlists/seclists/Discovery/Web-Content/common.txt',
        'subdomains': '/usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt',
        'passwords': '/usr/share/wordlists/seclists/Passwords/rockyou.txt'
    },
    
    # Port configurations
    'ports': {
        'default': '80,443,8080,8443',  # Standard web ports
        'hidden': '3000-4000,5000-6000', # Uncommon ranges
        'full': '1-65535',              # All ports
        'common_web': '81,591,2082...', # Additional web ports
        'database': '1433,1521,3306...' # Database ports
    },
    
    # Output settings
    'output_dir': 'scan_results',
    'screenshots_dir': 'screenshots',
    
    # Scan limits
    'max_pages': 100,        # Maximum pages to spider
    'max_depth': 5,          # Maximum directory depth
    'max_threads': 15,       # Default maximum threads
    'rate_limit_delay': 0.1  # Base delay between requests
}
Sample Report Output
Reports include comprehensive findings in structured format:

json
{
  "metadata": {
    "url": "https://example.com",
    "timestamp": "2023-11-15T12:34:56",
    "execution_time": 125.7
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
          "version": "nginx/1.18.0",
          "vulnerabilities": []
        }
      }
    },
    "web": {
      "technologies": {
        "Nginx": {
          "version": "1.18.0",
          "confidence": 100
        },
        "WordPress": {
          "version": "5.7.2",
          "plugins": ["woocommerce"]
        }
      }
    }
  }
}
Best Practices
Legal Compliance
Always obtain proper authorization before scanning any website. The tool includes automatic robots.txt checking by default.

Stealth Scanning
For sensitive environments, use:

bash
python webscan.py https://example.com \
    --rate-limit 2 \
    --random-delay \
    -t 5 \
    --no-selenium
Resource Management
Large sites may require increased timeouts:

python
# In webscan.py
CONFIG['timeouts']['requests'] = 30
CONFIG['timeouts']['selenium'] = 120
Output Management
Generate timestamped reports:

bash
python webscan.py https://example.com -o html -s
mv scan_results/report.html scan_results/example_com_$(date +%Y%m%d).html
Limitations
Browser Requirements
JavaScript-heavy sites require Chrome/Chromium installation for full analysis.

Security Systems
Aggressive scanning (-a flag) may trigger WAF/IDS protections.

Resource Intensive
Comprehensive scans require:

Minimum 2GB RAM

2 CPU cores

1GB disk space for reports
