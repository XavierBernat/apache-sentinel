"""
detectors/bot_detector.py - Malicious bot detector
"""

import re
from typing import Dict, Optional
from detectors.base_detector import BaseDetector

class BotDetector(BaseDetector):
    """Detector specialized in malicious bots and crawlers"""

    def __init__(self):
        super().__init__()
        self.name = "MALICIOUS_BOT"

        # Malicious bot User-Agent patterns
        self.bot_patterns = [
            # Vulnerability scanning tools
            r'(?i)(nikto|nmap|masscan|nessus|openvas|acunetix|burp|zap)',

            # SQL injection tools
            r'(?i)(sqlmap|havij|sqlninja|sqlsus|bbqsql)',

            # Exploitation frameworks
            r'(?i)(metasploit|beef|empire|covenant|cobalt strike)',

            # Generic web scrapers
            r'(?i)(scrapy|mechanize|wget|curl|libwww-perl|python-requests)',

            # Spam bots
            r'(?i)(spambot|spam bot|emailharvest|email harvest|emailsiphon)',

            # DDoS bots
            r'(?i)(slowloris|rudy|hulk|goldeneye|wreckuests)',

            # Fuzzing tools
            r'(?i)(wfuzz|ffuf|gobuster|dirb|dirbuster|dirsearch)',

            # Suspicious HTTP clients
            r'(?i)(go-http-client|java/\d|ruby|perl|php)',

            # Empty or suspicious user agents
            r'^-$',
            r'^$',
            r'(?i)^(bot|crawler|spider|scraper|scanner|scan|test|check)$',

            # Pentesting tools
            r'(?i)(hydra|medusa|patator|thc-|john|hashcat)',

            # Cryptocurrency bots
            r'(?i)(crypto|miner|coinhive|cryptoloot|monero)',

            # Information gathering tools
            r'(?i)(shodan|censys|zoomeye|fofa|hunter)',

            # WordPress scanners
            r'(?i)(wpscan|wpforce|wprecon|wp-login)',

            # Other suspicious patterns
            r'(?i)(eval|base64|shell|cmd|exec|system)',
            r'(?i)(hack|exploit|payload|backdoor|trojan)',
        ]

        self.compiled_patterns = [re.compile(pattern) for pattern in self.bot_patterns]

        # Known legitimate bots (partial whitelist)
        self.legitimate_bots = [
            'googlebot', 'bingbot', 'slurp', 'duckduckbot',
            'baiduspider', 'yandexbot', 'facebookexternalhit',
            'twitterbot', 'linkedinbot', 'whatsapp', 'applebot'
        ]

    def analyze(self, log_entry: Dict) -> Optional[Dict]:
        """Detect malicious bots based on User-Agent"""

        user_agent = log_entry.get('user_agent', '').lower()

        # Empty user agent is suspicious
        if not user_agent or user_agent == '-':
            return {
                'type': self.name,
                'subtype': 'EMPTY_USER_AGENT',
                'ip': log_entry['ip'],
                'timestamp': log_entry['timestamp'],
                'method': log_entry['method'],
                'path': log_entry['path'],
                'status': log_entry['status'],
                'user_agent': log_entry['user_agent'],
                'line_number': log_entry.get('line_number', 0)
            }

        # Check if it's a legitimate bot
        is_legitimate = any(bot in user_agent for bot in self.legitimate_bots)
        if is_legitimate:
            return None

        # Search for malicious bot patterns
        for pattern in self.compiled_patterns:
            match = pattern.search(user_agent)
            if match:
                # Identify bot type if possible
                bot_type = 'UNKNOWN'
                matched_text = match.group(0).lower()

                if any(tool in matched_text for tool in ['nikto', 'nmap', 'burp', 'zap', 'acunetix']):
                    bot_type = 'VULNERABILITY_SCANNER'
                elif any(tool in matched_text for tool in ['sqlmap', 'havij']):
                    bot_type = 'SQL_INJECTION_TOOL'
                elif any(tool in matched_text for tool in ['metasploit', 'beef', 'empire']):
                    bot_type = 'EXPLOITATION_FRAMEWORK'
                elif any(tool in matched_text for tool in ['wget', 'curl', 'scrapy']):
                    bot_type = 'WEB_SCRAPER'
                elif any(tool in matched_text for tool in ['wfuzz', 'dirb', 'gobuster']):
                    bot_type = 'DIRECTORY_FUZZER'
                elif any(tool in matched_text for tool in ['hydra', 'medusa', 'patator']):
                    bot_type = 'BRUTE_FORCE_TOOL'
                elif any(tool in matched_text for tool in ['crypto', 'miner', 'monero']):
                    bot_type = 'CRYPTO_MINER'

                return {
                    'type': self.name,
                    'subtype': bot_type,
                    'ip': log_entry['ip'],
                    'timestamp': log_entry['timestamp'],
                    'method': log_entry['method'],
                    'path': log_entry['path'],
                    'status': log_entry['status'],
                    'user_agent': log_entry['user_agent'],
                    'matched_pattern': matched_text,
                    'line_number': log_entry.get('line_number', 0)
                }

        return None