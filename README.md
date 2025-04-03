# **Ultimate Reconnaissance Tool**  
## **Advanced Website & Network Scanner** (Rust + Go + AI)  

### 📌 **Table of Contents**  
- [Installation](#installation)  
- [Basic Usage](#basic-usage)  
- [Advanced Scanning](#advanced-scanning)  
- [Subdomain Enumeration](#subdomain-enumeration)  
- [Vulnerability Scanning](#vulnerability-scanning)  
- [Stealth & OPSEC](#stealth--opsec)  
- [Continuous Monitoring](#continuous-monitoring)  
- [Reporting](#reporting)  
- [Legal & Ethics](#legal--ethics)  
- [Troubleshooting](#troubleshooting)  

---

## ⚡ **Installation**  

### **Dependencies**  
Ensure you have the necessary dependencies installed:  
```bash
# Kali Linux / Debian
sudo apt update && sudo apt install -y git rustc golang python3 python3-pip nmap nuclei subfinder
```

### **Build from Source**  
```bash
git clone https://github.com/Vikash-mn/webscan.git
cd webscan

# Build Rust components
cd rust && cargo build --release && cp target/release/scanner ../bin/

# Build Go modules
cd ../go && go build -o ../bin/subdomain_scanner subdomains.go && go build -o ../bin/vuln_scanner vulnerabilities.go

# Set up Python AI
cd ../ai && python3 -m venv venv && source venv/bin/activate && pip install -r requirements.txt
```

---

## 🔍 **Basic Usage**  

### **Quick Scan (Recommended for Initial Recon)**  
```bash
./bin/scanner example.com | tee quick_scan.json
```
**Scans:**  
💚 Open ports (80, 443, 8080)  
💚 Web technologies (CMS, frameworks)  
💚 TLS/SSL security  
💚 Lightweight subdomain check  

**Output Example:**  
```json
{
  "target": "example.com",
  "ports": [80, 443],
  "technologies": ["Nginx", "React"],
  "tls": {
    "grade": "A+",
    "weak_ciphers": false
  }
}
```

---

## 🚀 **Advanced Scanning**  

### **1. Full Port Scan (1-65535)**  
```bash
./bin/scanner -p 1-65535 --aggressive example.com > deep_scan.json
```
| **Flag**        | **Purpose** |
|----------------|------------|
| `-p 1-65535`   | Scan all ports |
| `--aggressive` | Enable service/version detection |
| `--stealth 3`  | Add 3s delay between probes |

### **2. Industrial Systems Scan**  
```bash
./bin/scanner -p 21,22,80,443,502,102,3389 --scada example.com
```
🔧 **Targets:**  
- **PLCs** (Port 502 - Modbus)  
- **OT systems** (Port 102 - Siemens S7)  
- **RDP** (Port 3389)  

---

## 🌐 **Subdomain Enumeration**  

### **1. Fast Subdomain Discovery**  
```bash
./bin/subdomain_scanner -t 50 -o subs.txt example.com
```
| **Flag** | **Purpose** |
|---------|------------|
| `-t 50` | Use 50 threads |
| `-o subs.txt` | Save results to file |

### **2. Check for Subdomain Takeovers**  
```bash
nuclei -l subs.txt -t ~/nuclei-templates/takeovers/
```
💡 **Critical Checks:**  
- AWS S3 buckets (`s3.example.com`)  
- GitHub Pages (`dev.example.com`)  
- Heroku (`staging.example.com`)  

---

## 💣 **Vulnerability Scanning**  

### **1. Critical/HIGH CVEs Only**  
```bash
./bin/vuln_scanner -severity critical,high -ep example.com
```
**Output Example:**  
```json
{
  "CVE-2023-1234": {
    "risk": "RCE",
    "confirmed": true,
    "poc": "https://vulndb.com/1234"
  }
}
```

### **2. Scan Multiple Targets**  
```bash
cat targets.txt | xargs -P 10 -I {} ./bin/vuln_scanner -severity high {}
```
🚀 **Parallelism:** `-P 10` → 10 concurrent scans  

---

## 👻 **Stealth & OPSEC**  

### **1. Tor Routing**  
```bash
proxychains ./bin/scanner --delay 10-30 example.com
```
### **2. Decoy IPs (Evade Firewalls)**  
```bash
./bin/scanner --decoy 192.168.1.5,192.168.1.6 example.com
```
### **3. Random User Agents**  
```bash
./bin/scanner --random-ua --jitter 5-15 example.com
```

---

## 📊 **Reporting**  

### **1. Generate HTML Dashboard**  
```bash
python3 reporter.py scan.json --format html > report.html
```
📈 **Includes:**  
- Risk heatmaps  
- Timeline of changes  
- Exploitability matrix  

### **2. Executive Summary**  
```bash
python3 reporter.py scan.json --brief
```

---

## ⚖️ **Legal & Ethics**  

👍 **Legal Uses**  
✔ Authorized pentesting  
✔ Bug bounty programs  
✔ Asset inventory  

🛑 **Illegal Uses**  
✖ Scanning without permission  
✖ Exploiting vulnerabilities  

---

🔒 **Use Responsibly. Happy (Ethical) Hacking!** 🚀  

