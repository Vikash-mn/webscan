#!/usr/bin/env python3
"""
ULTIMATE Website Reconnaissance & Vulnerability Assessment Tool
Author: Security Expert
Version: 3.1 - "The Omniscanner Plus"
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
from functools import lru_cache
from typing import Dict, List, Optional, Set, Tuple
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
from selenium.webdriver.common.by import By
from wappalyzer import Wappalyzer, WebPage
from urllib3.util.retry import Retry
from requests.adapters import HTTPAdapter

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
    'max_threads': 15, # Max concurrent threads
    'rate_limit_delay': 0.1, # Delay between requests in seconds
}

class WebTechnologyDetector:
    def __init__(self, url: str):
        self.url = url
        self.cache = {}
        self.common_tech_patterns = {
            'jQuery': r'jquery[.-](\d+\.\d+\.\d+)',
            'Bootstrap': r'bootstrap[.-](\d+\.\d+\.\d+)',
            'React': r'react[.-](\d+\.\d+\.\d+)',
            'Vue': r'vue[.-](\d+\.\d+\.\d+)',
            'Angular': r'angular[.-](\d+\.\d+\.\d+)',
            'WordPress': r'wordpress[.-](\d+\.\d+\.\d+)',
            'Drupal': r'drupal[.-](\d+\.\d+\.\d+)',
            'Laravel': r'laravel[.-](\d+\.\d+\.\d+)'
        }
    
    def get_response(self) -> Optional[requests.Response]:
        """Get HTTP response with caching and retries"""
        if 'response' in self.cache:
            return self.cache['response']
        
        try:
            session = requests.Session()
            retries = Retry(total=3, backoff_factor=1, status_forcelist=[500, 502, 503, 504])
            session.mount('http://', HTTPAdapter(max_retries=retries))
            session.mount('https://', HTTPAdapter(max_retries=retries))
            
            response = session.get(
                self.url,
                headers={
                    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
                },
                timeout=10
            )
            self.cache['response'] = response
            return response
        except Exception as e:
            print(f"Failed to fetch URL: {str(e)}")
            return None

    def detect_web_technologies(self) -> Dict:
        """Enhanced technology detection with comprehensive checks"""
        result = {
            'server': {},
            'frameworks': {},
            'programming_languages': {},
            'javascript': {},
            'database': {},
            'cms': {},
            'ecommerce': {},
            'analytics': {},
            'cdn': {},
            'security': {},
            'other': {},
            'meta': {
                'timestamp': int(time.time()),
                'url': self.url
            }
        }
        
        try:
            # Initial detection using Wappalyzer if available
            self.detect_with_wappalyzer(result)
            
            # Get response for manual checks
            response = self.get_response()
            if response:
                # Perform various detection methods
                self.detect_from_headers(response, result)
                self.detect_from_html(response.text, result)
                self.detect_from_cookies(response.cookies, result)
                self.detect_from_scripts(response.text, result)
                
                # Check common technology signatures
                self.check_common_tech_signatures(response.text, str(response.headers), result)
                
                # Specialized checks
                self.check_wordpress(response.text, result)
                self.check_react_vue_angular(response.text, result)
                self.check_ecommerce_platforms(response.text, result)
                self.check_security_headers(response.headers, result)
            
            # Final processing
            self.process_results(result)
            
        except Exception as e:
            result['error'] = str(e)
            result['status'] = 'error'
        else:
            result['status'] = 'success'
        
        return result
    
    def detect_with_wappalyzer(self, result: Dict):
        """Detect technologies using Wappalyzer if available"""
        try:
            from wappalyzer import Wappalyzer, WebPage
            wappalyzer = Wappalyzer.latest()
            webpage = WebPage.new_from_url(self.url)
            technologies = wappalyzer.analyze_with_versions_and_categories(webpage)
            
            for tech, data in technologies.items():
                category = data.get('categories', ['other'])[0].lower()
                target_dict = self._get_target_category(category, result)
                
                # Enhanced version detection
                self._process_versions(data)
                
                # Add technology to appropriate category
                target_dict[tech] = data
                
        except ImportError:
            pass  # Wappalyzer not available
        except Exception as e:
            result['wappalyzer_error'] = str(e)
    
    def _get_target_category(self, category: str, result: Dict) -> Dict:
        """Get the appropriate result category based on Wappalyzer category"""
        category_mapping = {
            'server': 'server',
            'web servers': 'server',
            'framework': 'frameworks',
            'javascript': 'javascript',
            'programming languages': 'programming_languages',
            'database': 'database',
            'cms': 'cms',
            'ecommerce': 'ecommerce',
            'analytics': 'analytics',
            'cdn': 'cdn',
            'security': 'security'
        }
        return result.get(category_mapping.get(category, 'other'), result['other'])
    
    def _process_versions(self, data: Dict):
        """Process and enhance version information"""
        if 'versions' in data and data['versions']:
            data['latest_version'] = max(data['versions'])
            data['version_count'] = len(data['versions'])
        else:
            version = self.extract_version_from_headers(data.get('name', ''))
            if version:
                data['versions'] = [version]
                data['latest_version'] = version
                data['version_count'] = 1
    
    def detect_from_headers(self, response: requests.Response, result: Dict):
        """Detect technologies from HTTP headers"""
        headers = response.headers
        
        # Server detection
        if 'server' in headers:
            server = headers['server']
            if 'Apache' in server:
                result['server']['Apache'] = self._parse_server_version(server)
            elif 'nginx' in server.lower():
                result['server']['Nginx'] = self._parse_server_version(server)
            elif 'IIS' in server:
                result['server']['IIS'] = self._parse_server_version(server)
            elif 'cloudflare' in server.lower():
                result['cdn']['Cloudflare'] = {'version': self._parse_server_version(server)}
        
        # PHP detection
        if 'X-Powered-By' in headers and 'PHP' in headers['X-Powered-By']:
            result['programming_languages']['PHP'] = {
                'versions': [self.extract_version_from_string(headers['X-Powered-By'])],
                'latest_version': self.extract_version_from_string(headers['X-Powered-By']),
                'detected_by': 'X-Powered-By header'
            }
        
        # ASP.NET detection
        if 'X-AspNet-Version' in headers:
            result['frameworks']['ASP.NET'] = {
                'versions': [headers['X-AspNet-Version']],
                'latest_version': headers['X-AspNet-Version'],
                'detected_by': 'X-AspNet-Version header'
            }
        
        # CDN detection
        if 'via' in headers:
            if 'cloudflare' in headers['via'].lower():
                result['cdn']['Cloudflare'] = {'detected_by': 'Via header'}
            elif 'akamai' in headers['via'].lower():
                result['cdn']['Akamai'] = {'detected_by': 'Via header'}
    
    def detect_from_html(self, html: str, result: Dict):
        """Detect technologies from HTML content"""
        # Meta generator tags
        meta_generator = re.search(r'<meta name="generator" content="([^"]+)"', html, re.I)
        if meta_generator:
            generator = meta_generator.group(1)
            if 'wordpress' in generator.lower():
                result['cms']['WordPress'] = {
                    'versions': [self.extract_version_from_string(generator)],
                    'detected_by': 'meta generator tag'
                }
            elif 'drupal' in generator.lower():
                result['cms']['Drupal'] = {
                    'versions': [self.extract_version_from_string(generator)],
                    'detected_by': 'meta generator tag'
                }
    
    def detect_from_cookies(self, cookies, result: Dict):
        """Detect technologies from cookies"""
        for cookie in cookies:
            if 'wordpress' in cookie.name.lower():
                result['cms']['WordPress'] = {'detected_by': 'cookie'}
            elif 'drupal' in cookie.name.lower():
                result['cms']['Drupal'] = {'detected_by': 'cookie'}
            elif 'magento' in cookie.name.lower():
                result['ecommerce']['Magento'] = {'detected_by': 'cookie'}
    
    def detect_from_scripts(self, html: str, result: Dict):
        """Detect technologies from script references"""
        script_pattern = re.compile(r'<script[^>]+src=["\']([^"\']+)["\']', re.I)
        for match in script_pattern.finditer(html):
            src = match.group(1)
            if 'jquery' in src:
                version = self.extract_version_from_string(src)
                result['javascript'].setdefault('jQuery', {
                    'versions': [],
                    'detected_by': 'script reference'
                })['versions'].append(version)
            elif 'react' in src:
                version = self.extract_version_from_string(src)
                result['javascript'].setdefault('React', {
                    'versions': [],
                    'detected_by': 'script reference'
                })['versions'].append(version)
    
    def check_common_tech_signatures(self, html: str, headers: str, result: Dict):
        """Check for common technology signatures"""
        # Check for common patterns
        for tech, pattern in self.common_tech_patterns.items():
            match = re.search(pattern, html, re.I)
            if match:
                category = self._determine_tech_category(tech)
                result[category].setdefault(tech, {
                    'versions': [],
                    'detected_by': 'pattern matching'
                })['versions'].append(match.group(1))
        
        # Check for Google Analytics
        if 'google-analytics.com/analytics.js' in html or 'gtag.js' in html:
            result['analytics']['Google Analytics'] = {'detected_by': 'script reference'}
        
        # Check for Cloudflare
        if 'cloudflare' in headers.lower():
            result['cdn']['Cloudflare'] = {'detected_by': 'headers'}
    
    def _determine_tech_category(self, tech: str) -> str:
        """Determine which category a technology belongs to"""
        category_map = {
            'jQuery': 'javascript',
            'React': 'javascript',
            'Vue': 'javascript',
            'Angular': 'javascript',
            'Bootstrap': 'frameworks',
            'WordPress': 'cms',
            'Drupal': 'cms',
            'Laravel': 'frameworks'
        }
        return category_map.get(tech, 'other')
    
    def check_wordpress(self, html: str, result: Dict):
        """Specialized WordPress detection"""
        if 'wp-content' in html or 'wp-includes' in html or 'wp-json' in html:
            wp_data = result['cms'].setdefault('WordPress', {
                'detected_by': 'path or API reference',
                'versions': []
            })
            
            # Try to get WordPress version from meta tag
            version = re.search(r'content="WordPress (\d+\.\d+\.\d+)"', html)
            if version:
                wp_data['versions'].append(version.group(1))
                wp_data['latest_version'] = version.group(1)
            
            # Check for WordPress plugins
            plugins = set(re.findall(r'wp-content/plugins/([^/]+)', html))
            if plugins:
                wp_data['plugins'] = list(plugins)
    
    def check_react_vue_angular(self, html: str, result: Dict):
        """Check for frontend frameworks"""
        # React
        if '__REACT_DEVTOOLS_GLOBAL_HOOK__' in html or 'react-dom' in html:
            result['javascript'].setdefault('React', {
                'detected_by': 'global variable or script reference',
                'versions': []
            })
        
        # Vue.js
        if '__VUE__' in html or 'vue.min.js' in html:
            result['javascript'].setdefault('Vue.js', {
                'detected_by': 'global variable or script reference',
                'versions': []
            })
        
        # Angular
        if 'ng-app' in html or 'angular.min.js' in html:
            result['javascript'].setdefault('Angular', {
                'detected_by': 'directive or script reference',
                'versions': []
            })
    
    def check_ecommerce_platforms(self, html: str, result: Dict):
        """Check for ecommerce platforms"""
        # Shopify
        if 'shopify' in html.lower() or 'cdn.shopify.com' in html:
            result['ecommerce']['Shopify'] = {'detected_by': 'shopify reference'}
        
        # WooCommerce (WordPress plugin)
        if 'woocommerce' in html.lower() or 'wc-api' in html:
            result['ecommerce']['WooCommerce'] = {'detected_by': 'woocommerce reference'}
            if 'WordPress' not in result['cms']:
                result['cms']['WordPress'] = {'detected_by': 'woocommerce implies wordpress'}
        
        # Magento
        if 'magento' in html.lower() or '/static/version' in html:
            result['ecommerce']['Magento'] = {'detected_by': 'magento reference'}
    
    def check_security_headers(self, headers: Dict, result: Dict):
        """Check for security-related headers and technologies"""
        security_techs = []
        
        if 'x-frame-options' in headers:
            security_techs.append('X-Frame-Options')
        if 'content-security-policy' in headers:
            security_techs.append('Content-Security-Policy')
        if 'x-content-type-options' in headers:
            security_techs.append('X-Content-Type-Options')
        if 'strict-transport-security' in headers:
            security_techs.append('HSTS')
        if 'x-xss-protection' in headers:
            security_techs.append('X-XSS-Protection')
        
        if security_techs:
            result['security']['headers'] = security_techs
    
    def process_results(self, result: Dict):
        """Post-process results to clean up and enhance data"""
        # Ensure versions are unique and sorted
        for category in result.values():
            if isinstance(category, dict):
                for tech, data in category.items():
                    if 'versions' in data and isinstance(data['versions'], list):
                        # Remove duplicates
                        data['versions'] = list(set(data['versions']))
                        # Sort versions
                        try:
                            data['versions'] = sorted(data['versions'], key=lambda v: [int(num) for num in v.split('.')])
                            data['latest_version'] = data['versions'][-1] if data['versions'] else None
                        except:
                            pass  # Version format not standard
    
    def _parse_server_version(self, server_string: str) -> Dict:
        """Parse server version information"""
        version = self.extract_version_from_string(server_string)
        return {
            'version': version,
            'raw': server_string
        }
    
    @staticmethod
    def extract_version_from_string(text: str) -> str:
        """Extract version number from string"""
        version = re.search(r'(\d+\.\d+(\.\d+)?(\.\d+)?)', text)
        return version.group(1) if version else 'unknown'
    
    def extract_version_from_headers(self, tech: str) -> Optional[str]:
        """Try to extract version from HTTP headers for specific technologies"""
        try:
            response = self.get_response()
            if not response:
                return None
                
            headers = response.headers
            
            if tech.lower() == 'php' and 'X-Powered-By' in headers:
                return self.extract_version_from_string(headers['X-Powered-By'])
            elif tech.lower() == 'asp.net' and 'X-AspNet-Version' in headers:
                return headers['X-AspNet-Version']
            elif tech.lower() == 'iis' and 'Server' in headers:
                return self.extract_version_from_string(headers['Server'])
            
            return None
        except:
            return None

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
                'tool_version': '3.1'
            },
            'findings': {}
        }
        self.visited_urls: Set[str] = set()
        self.lock = threading.Lock()
        self.rate_limit_last_call = 0
        self.session = self._init_session()
        self.selenium_driver = self.init_selenium()
        
    @staticmethod
    def normalize_url(url: str) -> str:
        """Ensure URL has proper scheme and format"""
        if not url.startswith(('http://', 'https://')):
            url = f'https://{url}'
        return url.rstrip('/')
    
    def _init_session(self) -> requests.Session:
        """Initialize requests session with random user agents and proper headers"""
        ua = UserAgent()
        session = requests.Session()
        
        # Configure retries
        retries = Retry(
            total=3,
            backoff_factor=1,
            status_forcelist=[500, 502, 503, 504]
        )
        session.mount('http://', HTTPAdapter(max_retries=retries))
        session.mount('https://', HTTPAdapter(max_retries=retries))
        
        session.headers.update({
            'User-Agent': ua.random,
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1',
            'Cache-Control': 'max-age=0',
        })
        session.timeout = CONFIG['timeouts']['requests']
        session.verify = False  # Disable SSL verification for compatibility
        return session
    
    def init_selenium(self) -> webdriver.Chrome:
        """Initialize headless Chrome for JS-rendered content"""
        options = Options()
        options.add_argument('--headless')
        options.add_argument('--disable-gpu')
        options.add_argument('--no-sandbox')
        options.add_argument('--disable-dev-shm-usage')
        options.add_argument('--window-size=1920,1080')
        options.add_argument(f'user-agent={UserAgent().random}')
        
        # Additional security and performance options
        options.add_argument('--disable-extensions')
        options.add_argument('--disable-popup-blocking')
        options.add_argument('--disable-notifications')
        options.add_argument('--ignore-certificate-errors')
        
        # Try to find Chrome binary in common locations
        chrome_paths = [
            '/usr/bin/google-chrome',
            '/usr/bin/chromium',
            '/usr/bin/chromium-browser',
            '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome'
        ]
        
        for path in chrome_paths:
            if os.path.exists(path):
                options.binary_location = path
                break
        
        try:
            return webdriver.Chrome(options=options)
        except Exception as e:
            print(f"[-] Selenium initialization failed: {str(e)}")
            print("[*] Falling back to requests-only mode")
            return None
    
    def rate_limit(self):
        """Enforce rate limiting between requests"""
        elapsed = time.time() - self.rate_limit_last_call
        if elapsed < CONFIG['rate_limit_delay']:
            time.sleep(CONFIG['rate_limit_delay'] - elapsed)
        self.rate_limit_last_call = time.time()
    
    def run(self, full_scan: bool = False, hidden_ports: bool = False, aggressive: bool = False) -> Dict:
        """Execute exhaustive scan with parallel operations"""
        print(f"[*] Starting ULTIMATE scan of {self.url}")
        start_time = time.time()
        
        # Create output directories
        os.makedirs(CONFIG['output_dir'], exist_ok=True)
        os.makedirs(CONFIG['screenshots_dir'], exist_ok=True)
        
        # Prepare scan tasks
        scan_tasks = self._prepare_scan_tasks(full_scan, hidden_ports, aggressive)
        
        # Execute scans concurrently
        with concurrent.futures.ThreadPoolExecutor(max_workers=CONFIG['max_threads']) as executor:
            futures = {name: executor.submit(task) for name, task in scan_tasks.items()}
            completed = concurrent.futures.wait(futures.values())
            
            # Store results
            self._process_scan_results(futures)
        
        # Post-processing
        self._post_processing()
        
        # Calculate execution time
        self.results['metadata']['execution_time'] = time.time() - start_time
        
        # Clean up
        if self.selenium_driver:
            self.selenium_driver.quit()
        
        return self.results
    
    def _prepare_scan_tasks(self, full_scan: bool, hidden_ports: bool, aggressive: bool) -> Dict:
        """Prepare all scan tasks to be executed"""
        port_config = (
            CONFIG['ports']['full'] if full_scan else
            f"{CONFIG['ports']['default']},{CONFIG['ports']['hidden']},{CONFIG['ports']['common_web']}"
            if hidden_ports else CONFIG['ports']['default']
        )
        
        return {
            # Network layer scans
            'ip_dns': lambda: self.get_ip_and_dns(),
            'ports': lambda: self.scan_ports(port_config),
            'hidden_services': lambda: self.detect_hidden_services(),
            'dns_enum': lambda: self.dns_enumeration(),
            'cloud_assets': lambda: self.find_cloud_assets(),
            'whois': lambda: self.get_whois_info(),
            
            # Web layer scans
            'headers': lambda: self.fetch_http_headers(),
            'tech': lambda: self.detect_web_technologies(),
            'ssl': lambda: self.get_ssl_info(),
            'cms': lambda: self.detect_cms(),
            'cookies': lambda: self.analyze_cookies(),
            'robots': lambda: self.check_robots_txt(),
            'sitemap': lambda: self.check_sitemap(),
            'dns_prefetch': lambda: self.check_dns_prefetch(),
            'cache_analysis': lambda: self.analyze_caching(),
            
            # Content analysis
            'spider': lambda: self.deep_spider(),
            'forms': lambda: self.extract_forms(),
            'comments': lambda: self.extract_comments_js(),
            'seo': lambda: self.analyze_seo(),
            'screenshot': lambda: self.take_screenshot(),
            'wordpress': lambda: self.scan_wordpress() if 'wordpress' in self.url.lower() else None,
            
            # Security checks
            'vulns': lambda: self.comprehensive_vuln_scan(),
            'cors': lambda: self.check_cors(),
            'headers_sec': lambda: self.check_security_headers(),
            'sensitive_files': lambda: self.find_sensitive_files(),
            'auth': lambda: self.check_auth_mechanisms(),
            'csrf': lambda: self.check_csrf(),
            'clickjacking': lambda: self.check_clickjacking(),
            'sql_injection': lambda: self.check_sql_injection(),
            'xss': lambda: self.check_xss(),
            'idor': lambda: self.check_idor(),
            
            # Performance
            'perf': lambda: self.analyze_performance(),
            
            # JavaScript analysis
            'js_analysis': lambda: self.analyze_javascript(),
            
            # API detection
            'api': lambda: self.detect_apis(),
        }
    
    def _process_scan_results(self, futures: Dict):
        """Process and organize all scan results"""
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
    
    def _post_processing(self):
        """Perform post-processing on scan results"""
        self.check_cloudflare()
        self.check_waf()
        self.generate_risk_assessment()
        self.calculate_hashes()
        self.analyze_relationships()
    
    # ======================
    # Network Layer Methods
    # ======================
    
    def get_ip_and_dns(self) -> Dict:
        """Comprehensive IP and DNS reconnaissance"""
        result = {'ip': [], 'dns': {}, 'geoip': {}, 'cdn': None}
        
        try:
            # Basic resolution (IPv4 and IPv6)
            result['ip'].extend(socket.getaddrinfo(self.domain, None))
            
            # Advanced DNS records with caching
            resolver = dns.resolver.Resolver()
            resolver.lifetime = 10  # Set timeout for DNS queries
            
            for record in ['A', 'AAAA', 'MX', 'NS', 'TXT', 'SOA', 'CNAME', 'PTR', 'SRV', 'SPF', 'DKIM', 'DMARC']:
                try:
                    answers = resolver.resolve(self.domain, record)
                    result['dns'][record] = [str(r) for r in answers]
                except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
                    continue
            
            # Check for common CDNs
            cdn_headers = ['server', 'via', 'x-cdn', 'x-cache', 'cf-ray']
            try:
                response = self.session.get(self.url)
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
            
            if not ports:
                ports = CONFIG['ports']['default']
            
            print(f"[*] Scanning ports: {ports}")
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
            self.rate_limit()
            response = self.session.get(self.url, allow_redirects=True)
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
            
            # Check for security headers
            security_headers = [
                'X-Frame-Options',
                'X-Content-Type-Options',
                'X-XSS-Protection',
                'Referrer-Policy',
                'Feature-Policy',
                'Permissions-Policy'
            ]
            result['security_headers'] = {
                h: response.headers.get(h, 'MISSING') for h in security_headers
            }
            
        except Exception as e:
            result['error'] = str(e)
            
        return result
    
    def detect_web_technologies(self) -> Dict:
        """Enhanced technology detection with version fingerprinting and caching"""
        result = {}
        
        try:
            # First try with Wappalyzer
            wappalyzer = Wappalyzer.latest()
            webpage = WebPage.new_from_url(self.url)
            technologies = wappalyzer.analyze_with_versions_and_categories(webpage)
            
            # Then use our enhanced detector
            enhanced_detector = WebTechnologyDetector(self.url)
            enhanced_results = enhanced_detector.detect_web_technologies()
            
            # Merge results
            result = {**enhanced_results, **technologies}
            
            # Enhanced version detection
            for tech, data in result.items():
                if isinstance(data, dict):
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
        
        except Exception as e:
            result['error'] = str(e)
            
        return result
    
    def extract_version_from_headers(self, tech: str) -> Optional[str]:
        """Try to extract version from HTTP headers for specific technologies"""
        try:
            response = self.session.get(self.url)
            if not response:
                return None
                
            headers = response.headers
            
            if tech.lower() == 'php' and 'X-Powered-By' in headers:
                return self._extract_version_from_string(headers['X-Powered-By'])
            elif tech.lower() == 'asp.net' and 'X-AspNet-Version' in headers:
                return headers['X-AspNet-Version']
            elif tech.lower() == 'iis' and 'Server' in headers:
                return self._extract_version_from_string(headers['Server'])
            
            return None
        except:
            return None
    
    @staticmethod
    def _extract_version_from_string(text: str) -> str:
        """Extract version number from string"""
        version = re.search(r'(\d+\.\d+(\.\d+)?(\.\d+)?)', text)
        return version.group(1) if version else 'unknown'
    
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
        
        if not self.selenium_driver:
            result['error'] = 'Selenium not available'
            return result
        
        try:
            self.selenium_driver.get(self.url)
            time.sleep(3)  # Wait for JS to load
            
            # Get all links
            links = self.selenium_driver.find_elements(By.TAG_NAME, 'a')
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
                elements = self.selenium_driver.find_elements(By.TAG_NAME, tag)
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
    
    def recursive_spider(self, url: str, result: Dict, depth: int):
        """Recursively spider the website up to a certain depth"""
        if depth > CONFIG['max_depth'] or len(result['pages']) >= CONFIG['max_pages']:
            return
        
        try:
            self.rate_limit()
            self.selenium_driver.get(url)
            time.sleep(2)  # Wait for page to load
            
            # Get new links on this page
            links = self.selenium_driver.find_elements(By.TAG_NAME, 'a')
            new_links = []
            
            for link in links:
                try:
                    href = link.get_attribute('href')
                    if href and href not in self.visited_urls and self.domain in href:
                        new_links.append(href)
                        self.visited_urls.add(href)
                except:
                    continue
            
            # Process new links
            for link in new_links[:10]:  # Limit to 10 links per page to avoid explosion
                try:
                    self.selenium_driver.get(link)
                    time.sleep(1)
                    
                    page_info = {
                        'url': self.selenium_driver.current_url,
                        'title': self.selenium_driver.title,
                        'source': self.selenium_driver.page_source[:500] + '...',
                        'screenshot': f"{CONFIG['screenshots_dir']}/{hashlib.md5(link.encode()).hexdigest()}.png",
                    }
                    
                    self.selenium_driver.save_screenshot(page_info['screenshot'])
                    result['pages'].append(page_info)
                    
                    # Recurse
                    self.recursive_spider(link, result, depth + 1)
                except:
                    continue
                    
        except Exception as e:
            print(f"[-] Error during spidering: {str(e)}")
    
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
    
    def check_admin_interfaces(self) -> List[str]:
        """Check for common admin interfaces"""
        admin_paths = [
            '/admin', '/wp-admin', '/administrator', '/manager', 
            '/cpanel', '/whm', '/webadmin', '/adminpanel',
            '/backend', '/console', '/controlpanel'
        ]
        
        found = []
        for path in admin_paths:
            try:
                url = urljoin(self.base_url, path)
                response = self.session.get(url, timeout=5)
                if response.status_code < 400:  # 2xx or 3xx
                    found.append({
                        'url': url,
                        'status': response.status_code,
                        'title': BeautifulSoup(response.text, 'html.parser').title.string if response.text else None
                    })
            except:
                continue
                
        return found
    
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
    
    def analyze_relationships(self):
        """Analyze relationships between different findings"""
        # Example: Check if outdated technologies have known vulnerabilities
        tech = self.results['findings']['web']['technologies']
        vulns = self.results['findings']['security']['vulnerabilities']
        
        if isinstance(tech, dict) and isinstance(vulns, dict):
            outdated = []
            for name, data in tech.items():
                if 'latest_version' in data and 'versions' in data:
                    current = data['versions'][0]
                    latest = data['latest_version']
                    if current != latest:
                        outdated.append({
                            'technology': name,
                            'current': current,
                            'latest': latest,
                            'vulnerabilities': [
                                v for v in vulns.get('nuclei', [])
                                if name.lower() in v.get('templateID', '').lower()
                            ]
                        })
            
            if outdated:
                self.results['findings']['security']['outdated_technologies'] = outdated
    
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
    
    def generate_html_report(self, filepath: str):
        """Generate a comprehensive HTML report"""
        try:
            from jinja2 import Environment, FileSystemLoader
            
            env = Environment(loader=FileSystemLoader('templates'))
            template = env.get_template('report.html')
            
            with open(filepath, 'w') as f:
                f.write(template.render(
                    results=self.results,
                    timestamp=datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                ))
        except Exception as e:
            with open(filepath, 'w') as f:
                f.write(f"<html><body><h1>Error generating report: {str(e)}</h1></body></html>")

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
    parser.add_argument('-t', '--threads', type=int, default=CONFIG['max_threads'], help="Maximum threads to use")
    
    args = parser.parse_args()
    
    # Update config based on arguments
    CONFIG['max_threads'] = args.threads
    
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
    import threading  # Added for thread safety
    main()
