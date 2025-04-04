#!/usr/bin/env python3
"""
ULTIMATE Website Reconnaissance & Vulnerability Assessment Tool
Author: Security Expert
Version: 3.0 - "The Omniscanner"
"""

import argparse
import concurrent.futures
import hashlib
import json
import os
import re
import socket
import ssl
import subprocess
import sys
import time
import urllib.robotparser
from datetime import datetime
from urllib.parse import urljoin, urlparse

import dns.resolver
import nmap
import requests
import sslyze
from bs4 import BeautifulSoup
from cryptography import x509
from fake_useragent import UserAgent
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from wappalyzer import Wappalyzer, WebPage

# Configuration
CONFIG = {
    'timeouts': {
        'requests': 20,
        'selenium': 60,
        'nmap': 1200,
        'subprocess': 900,
    },
    'wordlists': {
        'dirs': '/usr/share/wordlists/dirb/common.txt',
        'subdomains': '/usr/share/wordlists/subdomains-top1million-5000.txt',
        'passwords': '/usr/share/wordlists/rockyou.txt',
    },
    'ports': {
        'default': '80,443,8080,8443,8888,4443,4444,10443,18080,28080',
        'hidden': '3000-4000,5000-6000,7000-8000,9000-10000',
        'full': '1-65535',
        'common_web': '81,591,2082,2087,2095,2096,3000,3306,4243,4567,4711,4712,4993,5000,5104,5108,5280,5281,5601,5800,6543,7000,7001,7002,7396,7474,8000,8001,8008,8014,8042,8069,8080,8081,8083,8088,8090,8091,8095,8118,8123,8172,8181,8222,8243,8280,8281,8333,8337,8443,8500,8530,8531,8834,8880,8888,8983,9000,9001,9043,9060,9080,9090,9091,9092,9200,9443,9502,9800,9981,10000,10250,11371,12443,16080,18091,18092,20720,28017',
        'database': '1433,1434,1521,1830,3306,3351,5432,5984,6379,7199,7474,7473,7687,8000,8087,8091,8142,8182,8529,8629,8666,8765,8843,8888,8983,9000,9042,9060,9070,9080,9091,9092,9200,9300,9418,9999,11211,27017,27018,28015,50000',
    },
    'output_dir': 'scan_results',
    'screenshots_dir': 'screenshots',
    'max_pages': 100,  # Limit for spidering
    'max_depth': 5,    # Max recursion depth
}

# Initialize session with random user agents
ua = UserAgent()
SESSION = requests.Session()
SESSION.headers.update({
    'User-Agent': ua.random,
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
    'Accept-Language': 'en-US,en;q=0.5',
    'Accept-Encoding': 'gzip, deflate',
    'Connection': 'keep-alive',
    'Upgrade-Insecure-Requests': '1',
    'Cache-Control': 'max-age=0',
})
SESSION.timeout = CONFIG['timeouts']['requests']
SESSION.verify = False  # Disable SSL verification for compatibility

class UltimateScanner:
    """ULTIMATE website scanner with exhaustive reconnaissance capabilities"""
    
    def __init__(self, url: str):
        self.url = self.normalize_url(url)
        self.domain = urlparse(self.url).hostname
        self.base_url = f"{urlparse(self.url).scheme}://{urlparse(self.url).netloc}"
        self.results = {
            'metadata': {
                'url': self.url,
                'domain': self.domain,
                'base_url': self.base_url,
                'timestamp': datetime.utcnow().isoformat(),
                'tool_version': '3.0'
            },
            'findings': {}
        }
        self.visited_urls = set()
        self.selenium_driver = self.init_selenium()
        
    @staticmethod
    def normalize_url(url: str) -> str:
        """Ensure URL has proper scheme"""
        if not url.startswith(('http://', 'https://')):
            return f'https://{url}'
        return url.rstrip('/')
    
    def init_selenium(self):
        """Initialize headless Chrome for JS-rendered content"""
        options = Options()
        options.add_argument('--headless')
        options.add_argument('--disable-gpu')
        options.add_argument('--no-sandbox')
        options.add_argument('--disable-dev-shm-usage')
        options.add_argument('--window-size=1920,1080')
        options.add_argument(f'user-agent={ua.random}')
        return webdriver.Chrome(options=options)
    
    def run(self, full_scan: bool = False, hidden_ports: bool = False, aggressive: bool = False) -> Dict:
        """Execute exhaustive scan with parallel operations"""
        print(f"[*] Starting ULTIMATE scan of {self.url}")
        
        # Create output directories
        os.makedirs(CONFIG['output_dir'], exist_ok=True)
        os.makedirs(CONFIG['screenshots_dir'], exist_ok=True)
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=15) as executor:
            # Network layer scans
            futures = {
                'ip_dns': executor.submit(self.get_ip_and_dns),
                'ports': executor.submit(
                    self.scan_ports, 
                    CONFIG['ports']['full'] if full_scan else (
                        f"{CONFIG['ports']['default']},{CONFIG['ports']['hidden']},{CONFIG['ports']['common_web']}" 
                        if hidden_ports else CONFIG['ports']['default']
                    )
                ),
                'hidden_services': executor.submit(self.detect_hidden_services),
                'dns_enum': executor.submit(self.dns_enumeration),
                'cloud_assets': executor.submit(self.find_cloud_assets),
                'whois': executor.submit(self.get_whois_info),
                
                # Web layer scans
                'headers': executor.submit(self.fetch_http_headers),
                'tech': executor.submit(self.detect_web_technologies),
                'ssl': executor.submit(self.get_ssl_info),
                'cms': executor.submit(self.detect_cms),
                'cookies': executor.submit(self.analyze_cookies),
                'robots': executor.submit(self.check_robots_txt),
                'sitemap': executor.submit(self.check_sitemap),
                'dns_prefetch': executor.submit(self.check_dns_prefetch),
                'cache_analysis': executor.submit(self.analyze_caching),
                
                # Content analysis
                'spider': executor.submit(self.deep_spider),
                'forms': executor.submit(self.extract_forms),
                'comments': executor.submit(self.extract_comments_js),
                'seo': executor.submit(self.analyze_seo),
                'screenshot': executor.submit(self.take_screenshot),
                'wordpress': executor.submit(self.scan_wordpress) if 'wordpress' in self.url.lower() else None,
                
                # Security checks
                'vulns': executor.submit(self.comprehensive_vuln_scan),
                'cors': executor.submit(self.check_cors),
                'headers_sec': executor.submit(self.check_security_headers),
                'sensitive_files': executor.submit(self.find_sensitive_files),
                'auth': executor.submit(self.check_auth_mechanisms),
                'csrf': executor.submit(self.check_csrf),
                'clickjacking': executor.submit(self.check_clickjacking),
                'sql_injection': executor.submit(self.check_sql_injection),
                'xss': executor.submit(self.check_xss),
                'idor': executor.submit(self.check_idor),
                
                # Performance
                'perf': executor.submit(self.analyze_performance),
                
                # JavaScript analysis
                'js_analysis': executor.submit(self.analyze_javascript),
                
                # API detection
                'api': executor.submit(self.detect_apis),
            }
            
            # Wait for all tasks to complete
            concurrent.futures.wait(futures.values())
            
            # Store results
            self.results['findings'] = {
                'network': {
                    'ip_dns': futures['ip_dns'].result(),
                    'open_ports': futures['ports'].result(),
                    'hidden_services': futures['hidden_services'].result(),
                    'dns_enumeration': futures['dns_enum'].result(),
                    'cloud_assets': futures['cloud_assets'].result(),
                    'whois': futures['whois'].result(),
                },
                'web': {
                    'headers': futures['headers'].result(),
                    'technologies': futures['tech'].result(),
                    'ssl_tls': futures['ssl'].result(),
                    'cms': futures['cms'].result(),
                    'cookies': futures['cookies'].result(),
                    'robots_txt': futures['robots'].result(),
                    'sitemap': futures['sitemap'].result(),
                    'dns_prefetch': futures['dns_prefetch'].result(),
                    'caching': futures['cache_analysis'].result(),
                },
                'content': {
                    'spidered': futures['spider'].result(),
                    'forms': futures['forms'].result(),
                    'comments': futures['comments'].result(),
                    'seo': futures['seo'].result(),
                    'screenshot': f"{CONFIG['screenshots_dir']}/{self.domain}.png",
                    'wordpress': futures['wordpress'].result() if futures['wordpress'] else None,
                },
                'security': {
                    'vulnerabilities': futures['vulns'].result(),
                    'cors': futures['cors'].result(),
                    'security_headers': futures['headers_sec'].result(),
                    'sensitive_files': futures['sensitive_files'].result(),
                    'authentication': futures['auth'].result(),
                    'csrf': futures['csrf'].result(),
                    'clickjacking': futures['clickjacking'].result(),
                    'sql_injection': futures['sql_injection'].result(),
                    'xss': futures['xss'].result(),
                    'idor': futures['idor'].result(),
                },
                'performance': futures['perf'].result(),
                'javascript': futures['js_analysis'].result(),
                'api': futures['api'].result(),
            }
        
        # Post-processing
        self.check_cloudflare()
        self.check_waf()
        self.generate_risk_assessment()
        self.calculate_hashes()
        
        # Clean up
        self.selenium_driver.quit()
        
        return self.results
    
    # ======================
    # Network Layer Methods
    # ======================
    
    def get_ip_and_dns(self) -> Dict:
        """Comprehensive IP and DNS reconnaissance"""
        result = {'ip': [], 'dns': {}, 'geoip': {}, 'cdn': None}
        
        try:
            # Basic resolution (IPv4 and IPv6)
            result['ip'].extend(socket.getaddrinfo(self.domain, None))
            
            # Advanced DNS records
            resolver = dns.resolver.Resolver()
            for record in ['A', 'AAAA', 'MX', 'NS', 'TXT', 'SOA', 'CNAME', 'PTR', 'SRV', 'SPF', 'DKIM', 'DMARC']:
                try:
                    answers = resolver.resolve(self.domain, record)
                    result['dns'][record] = [str(r) for r in answers]
                except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
                    continue
            
            # Check for common CDNs
            cdn_headers = ['server', 'via', 'x-cdn', 'x-cache', 'cf-ray']
            try:
                response = SESSION.get(self.url)
                for header in cdn_headers:
                    if header in response.headers:
                        result['cdn'] = response.headers[header]
                        break
            except:
                pass
                
        except Exception as e:
            result['error'] = str(e)
            
        return result
    
    def scan_ports(self, ports: str) -> Dict:
        """Ultimate port scanning with service and vulnerability detection"""
        result = {}
        
        try:
            nm = nmap.PortScanner()
            scan_args = '-sV -T4 --script=banner,vulners,ssl-enum-ciphers,http-title,http-headers,http-enum,http-sitemap-generator'
            nm.scan(hosts=self.domain, ports=ports, arguments=scan_args)
            
            for host in nm.all_hosts():
                result[host] = {}
                for proto in nm[host].all_protocols():
                    result[host][proto] = {}
                    for port, data in nm[host][proto].items():
                        if data['state'] == 'open':
                            service = {
                                'name': data.get('name', 'unknown'),
                                'product': data.get('product', ''),
                                'version': data.get('version', ''),
                                'cpe': data.get('cpe', ''),
                                'scripts': {},
                                'vulnerabilities': []
                            }
                            
                            # Extract script results
                            if 'script' in data:
                                for script, output in data['script'].items():
                                    service['scripts'][script] = output
                                    # Extract vulnerabilities from vulners script
                                    if script == 'vulners':
                                        vulns = []
                                        for line in output.split('\n'):
                                            if 'CVE-' in line:
                                                vulns.append(line.strip())
                                        service['vulnerabilities'] = vulns
                            
                            result[host][proto][port] = service
            
            # Perform deeper HTTP analysis on web ports
            self.analyze_web_ports(result)
            
        except Exception as e:
            result['error'] = str(e)
            
        return result
    
    def detect_hidden_services(self) -> Dict:
        """Deep detection for hidden/less-common web services"""
        result = {}
        
        try:
            # Combine all potential web ports
            web_ports = list(set(
                [int(p) for p in CONFIG['ports']['common_web'].split(',')] +
                [int(p) for p in CONFIG['ports']['default'].split(',')] +
                [int(p) for p in CONFIG['ports']['hidden'].split(',') if '-' not in p]
            ))
            
            with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
                futures = {port: executor.submit(self.check_port_service, port) for port in web_ports}
                for port, future in futures.items():
                    try:
                        service_info = future.result()
                        if service_info:
                            result[port] = service_info
                    except:
                        continue
            
            # Special checks
            self.check_websockets(result)
            self.check_graphql(result)
            self.check_grpc(result)
            
        except Exception as e:
            result['error'] = str(e)
            
        return result
    
    def check_port_service(self, port: int) -> Optional[Dict]:
        """Check a single port for web services"""
        try:
            # Try HTTP
            http_url = f"http://{self.domain}:{port}"
            response = requests.get(http_url, timeout=5, verify=False, allow_redirects=True)
            if response.status_code < 500:  # Accept even 4xx as valid responses
                soup = BeautifulSoup(response.text, 'html.parser')
                title = soup.title.string if soup.title else None
                
                service_info = {
                    'protocol': 'http',
                    'status': response.status_code,
                    'title': title,
                    'headers': dict(response.headers),
                    'content_type': response.headers.get('Content-Type', ''),
                    'body_hash': hashlib.sha256(response.content).hexdigest(),
                    'body_length': len(response.content),
                }
                
                # Check for API indicators
                if 'application/json' in response.headers.get('Content-Type', ''):
                    service_info['api'] = True
                    try:
                        service_info['json_sample'] = response.json()
                    except:
                        pass
                
                return service_info
            
            # Try HTTPS if HTTP didn't work
            https_url = f"https://{self.domain}:{port}"
            response = requests.get(https_url, timeout=5, verify=False, allow_redirects=True)
            if response.status_code < 500:
                soup = BeautifulSoup(response.text, 'html.parser')
                title = soup.title.string if soup.title else None
                
                service_info = {
                    'protocol': 'https',
                    'status': response.status_code,
                    'title': title,
                    'headers': dict(response.headers),
                    'content_type': response.headers.get('Content-Type', ''),
                    'body_hash': hashlib.sha256(response.content).hexdigest(),
                    'body_length': len(response.content),
                }
                
                # Get SSL info for HTTPS services
                try:
                    cert = ssl.get_server_certificate((self.domain, port))
                    x509_cert = x509.load_pem_x509_certificate(cert.encode())
                    service_info['ssl'] = {
                        'issuer': x509_cert.issuer.rfc4514_string(),
                        'subject': x509_cert.subject.rfc4514_string(),
                        'not_valid_before': x509_cert.not_valid_before.isoformat(),
                        'not_valid_after': x509_cert.not_valid_after.isoformat(),
                        'serial_number': str(x509_cert.serial_number),
                    }
                except:
                    pass
                
                return service_info
            
        except:
            return None
    
    # ======================
    # Web Layer Methods
    # ======================
    
    def fetch_http_headers(self) -> Dict:
        """Fetch headers with advanced analysis"""
        result = {}
        
        try:
            response = SESSION.get(self.url, allow_redirects=True)
            result = {
                'status_code': response.status_code,
                'final_url': response.url,
                'redirect_chain': [{'url': r.url, 'status': r.status_code} for r in response.history],
                'headers': dict(response.headers),
                'cookies': dict(response.cookies),
                'content_type': response.headers.get('Content-Type', ''),
                'content_length': len(response.content),
                'response_time': response.elapsed.total_seconds(),
                'server': response.headers.get('Server', ''),
                'x_powered_by': response.headers.get('X-Powered-By', ''),
                'content_security_policy': response.headers.get('Content-Security-Policy', ''),
                'strict_transport_security': response.headers.get('Strict-Transport-Security', ''),
            }
            
            # Check for HTTP/2
            result['http_version'] = 'HTTP/2' if response.raw.version == 20 else 'HTTP/1.1'
            
        except Exception as e:
            result['error'] = str(e)
            
        return result
    
    def detect_web_technologies(self) -> Dict:
        """Enhanced technology detection with version fingerprinting"""
        result = {}
        
        try:
            wappalyzer = Wappalyzer.latest()
            webpage = WebPage.new_from_url(self.url)
            technologies = wappalyzer.analyze_with_versions_and_categories(webpage)
            
            # Enhanced version detection
            for tech, data in technologies.items():
                if 'versions' in data and data['versions']:
                    data['latest_version'] = max(data['versions'])
                    data['version_count'] = len(data['versions'])
                else:
                    # Try to extract version from headers or HTML
                    version = self.extract_version_from_headers(tech)
                    if version:
                        data['versions'] = [version]
                        data['latest_version'] = version
                        data['version_count'] = 1
            
            result = technologies
        except Exception as e:
            result['error'] = str(e)
            
        return result
    
    def get_ssl_info(self) -> Dict:
        """Comprehensive SSL/TLS assessment with SSLyze"""
        result = {}
        
        try:
            # Basic SSL info
            hostname = self.domain
            context = ssl.create_default_context()
            
            with socket.create_connection((hostname, 443), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    cipher = ssock.cipher()
                    
                    # Certificate info
                    result['certificate'] = {
                        'subject': dict(x[0] for x in cert['subject']),
                        'issuer': dict(x[0] for x in cert['issuer']),
                        'validity': {
                            'not_before': cert['notBefore'],
                            'not_after': cert['notAfter'],
                            'expires_in_days': (ssl.cert_time_to_seconds(cert['notAfter']) - time.time()) / 86400,
                        },
                        'serial': cert.get('serialNumber', ''),
                        'version': cert.get('version', ''),
                        'extensions': cert.get('extensions', []),
                    }
                    
                    # Cipher info
                    result['cipher'] = {
                        'name': cipher[0],
                        'version': cipher[1],
                        'bits': cipher[2],
                    }
            
            # Advanced SSLyze scan
            try:
                scanner = sslyze.Scanner()
                command = sslyze.ScanCommand(
                    hostname=hostname,
                    scan_commands={
                        'ssl_2_0_cipher_suites',
                        'ssl_3_0_cipher_suites',
                        'tls_1_0_cipher_suites',
                        'tls_1_1_cipher_suites',
                        'tls_1_2_cipher_suites',
                        'tls_1_3_cipher_suites',
                        'heartbleed',
                        'openssl_ccs_injection',
                        'reneg',
                        'robot',
                        'session_resumption',
                        'compression',
                        'certificate_info',
                        'http_headers',
                    },
                )
                scan_result = scanner.run_scan_command(command)
                result['sslyze'] = scan_result.as_json()
            except:
                pass
            
        except Exception as e:
            result['error'] = str(e)
            
        return result
    
    # ======================
    # Content Analysis
    # ======================
    
    def deep_spider(self) -> Dict:
        """Advanced spidering with Selenium for JS-rendered content"""
        result = {
            'pages': [],
            'links': [],
            'external_links': [],
            'resources': [],
            'forms': [],
            'statistics': {
                'total_pages': 0,
                'internal_links': 0,
                'external_links': 0,
                'forms_found': 0,
            }
        }
        
        try:
            self.selenium_driver.get(self.url)
            time.sleep(3)  # Wait for JS to load
            
            # Get all links
            links = self.selenium_driver.find_elements_by_tag_name('a')
            for link in links:
                try:
                    href = link.get_attribute('href')
                    if href:
                        if self.domain in href:
                            result['links'].append(href)
                            result['statistics']['internal_links'] += 1
                        else:
                            result['external_links'].append(href)
                            result['statistics']['external_links'] += 1
                except:
                    continue
            
            # Get all resources
            for tag in ['img', 'script', 'link', 'iframe']:
                elements = self.selenium_driver.find_elements_by_tag_name(tag)
                for el in elements:
                    try:
                        src = el.get_attribute('src') or el.get_attribute('href')
                        if src:
                            result['resources'].append({
                                'type': tag,
                                'url': src,
                                'external': self.domain not in src
                            })
                    except:
                        continue
            
            # Get current page info
            current_page = {
                'url': self.selenium_driver.current_url,
                'title': self.selenium_driver.title,
                'source': self.selenium_driver.page_source[:1000] + '...' if len(self.selenium_driver.page_source) > 1000 else self.selenium_driver.page_source,
                'screenshot': f"{CONFIG['screenshots_dir']}/{self.domain}_home.png",
            }
            self.selenium_driver.save_screenshot(current_page['screenshot'])
            result['pages'].append(current_page)
            
            # Limited recursive spidering
            self.recursive_spider(self.url, result, depth=1)
            
            result['statistics']['total_pages'] = len(result['pages'])
            
        except Exception as e:
            result['error'] = str(e)
            
        return result
    
    # [Additional methods would continue here...]
    
    # ======================
    # Security Checks
    # ======================
    
    def comprehensive_vuln_scan(self) -> Dict:
        """Run multiple vulnerability scanners"""
        result = {
            'nikto': {},
            'nuclei': {},
            'zap': {},
            'manual_checks': {},
        }
        
        try:
            # Nikto scan
            nikto_result = self.run_subprocess([
                'nikto', '-h', self.url, 
                '-Format', 'json',
                '-Tuning', 'x4567890abc'
            ])
            
            if nikto_result and not nikto_result.startswith('Error'):
                result['nikto'] = json.loads(nikto_result)
            else:
                result['nikto']['error'] = nikto_result
                
            # Nuclei scan
            nuclei_result = self.run_subprocess([
                'nuclei', '-u', self.url, 
                '-json',
                '-severity', 'low,medium,high,critical',
                '-templates', '/usr/local/nuclei-templates'
            ])
            
            if nuclei_result and not nuclei_result.startswith('Error'):
                result['nuclei'] = [json.loads(line) for line in nuclei_result.splitlines() if line.strip()]
            else:
                result['nuclei']['error'] = nuclei_result
                
            # Manual checks
            result['manual_checks'] = {
                'admin_interfaces': self.check_admin_interfaces(),
                'debug_endpoints': self.check_debug_endpoints(),
                'exposed_database_interfaces': self.check_database_interfaces(),
            }
            
        except Exception as e:
            result['error'] = str(e)
            
        return result
    
    # [Additional security methods would continue here...]
    
    # ======================
    # Utility Methods
    # ======================
    
    @staticmethod
    def run_subprocess(command: List[str]) -> str:
        """Execute subprocess command with error handling"""
        try:
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=CONFIG['timeouts']['subprocess']
            )
            return result.stdout if result.returncode == 0 else result.stderr
        except Exception as e:
            return f"Error: {str(e)}"
    
    # ======================
    # Output Methods
    # ======================
    
    def save_results(self, format: str = 'json', output_dir: str = None) -> str:
        """Save results to file with multiple format options"""
        if not output_dir:
            output_dir = CONFIG['output_dir']
            
        os.makedirs(output_dir, exist_ok=True)
        filename = f"{self.domain}_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        
        if format == 'json':
            filepath = os.path.join(output_dir, f"{filename}.json")
            with open(filepath, 'w') as f:
                json.dump(self.results, f, indent=2)
        elif format == 'html':
            filepath = os.path.join(output_dir, f"{filename}.html")
            self.generate_html_report(filepath)
        elif format == 'markdown':
            filepath = os.path.join(output_dir, f"{filename}.md")
            self.generate_markdown_report(filepath)
        else:
            filepath = os.path.join(output_dir, f"{filename}.txt")
            with open(filepath, 'w') as f:
                f.write(str(self.results))
                
        return filepath

def main():
    parser = argparse.ArgumentParser(
        description="ULTIMATE Website Reconnaissance & Vulnerability Assessment Tool",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    parser.add_argument('url', help="URL to scan")
    parser.add_argument('-f', '--full', action='store_true', help="Perform full scan (all ports)")
    parser.add_argument('-hp', '--hidden-ports', action='store_true', help="Scan for hidden/less-common web ports")
    parser.add_argument('-a', '--aggressive', action='store_true', help="Aggressive scanning (more intrusive checks)")
    parser.add_argument('-o', '--output', choices=['json', 'html', 'markdown', 'text'], default='json', help="Output format")
    parser.add_argument('-s', '--save', action='store_true', help="Save results to file")
    parser.add_argument('-v', '--verbose', action='store_true', help="Verbose output")
    
    args = parser.parse_args()
    
    print(f"[*] Starting ULTIMATE scan of {args.url}")
    scanner = UltimateScanner(args.url)
    results = scanner.run(full_scan=args.full, hidden_ports=args.hidden_ports, aggressive=args.aggressive)
    
    if args.save:
        report_path = scanner.save_results(format=args.output)
        print(f"[+] Report saved to {report_path}")
    else:
        if args.output == 'json':
            print(json.dumps(results, indent=2))
        elif args.output == 'html':
            print(scanner.generate_html_report())
        elif args.output == 'markdown':
            print(scanner.generate_markdown_report())
        else:
            print(results)

if __name__ == '__main__':
    main()