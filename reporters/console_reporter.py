"""
reporters/console_reporter.py - Console output report strategy
"""

from typing import Dict, Any, List
from collections import Counter, defaultdict
from reporters.base_reporter import BaseReporter

class ConsoleReporter(BaseReporter):
    """Console report implementation with readable formatting"""

    def __init__(self):
        self.colors = {
            'HEADER': '\033[95m',
            'BLUE': '\033[94m',
            'GREEN': '\033[92m',
            'YELLOW': '\033[93m',
            'RED': '\033[91m',
            'BOLD': '\033[1m',
            'UNDERLINE': '\033[4m',
            'END': '\033[0m'
        }

    def _print_header(self, text: str, level: int = 1):
        """Print formatted header"""
        if level == 1:
            print("\n" + "=" * 80)
            print(f"{self.colors['BOLD']}{text.center(80)}{self.colors['END']}")
            print("=" * 80)
        elif level == 2:
            print(f"\n{self.colors['BLUE']}[+] {text}{self.colors['END']}")
            print("-" * 40)
        else:
            print(f"\n{self.colors['YELLOW']}    • {text}{self.colors['END']}")

    def _print_stat(self, label: str, value: Any, indent: int = 4):
        """Print a statistic"""
        padding = " " * indent
        print(f"{padding}{label}: {value:,}" if isinstance(value, int) else f"{padding}{label}: {value}")

    def format_detection(self, detection: Dict) -> str:
        """Format a detection for console display"""
        return (f"    IP: {detection['ip']} | "
                f"Line: {detection.get('line_number', 'N/A')} | "
                f"Path: {detection['path'][:50]}...")

    def generate(self, report_data: Dict[str, Any]) -> None:
        """Generate complete console report"""

        # Main header
        self._print_header("SECURITY ANALYSIS REPORT", 1)

        # General statistics
        self._print_header("GENERAL STATISTICS", 2)
        self._print_stat("Total lines processed", report_data['total_lines'])
        self._print_stat("Successfully parsed lines", report_data['parsed_lines'])
        self._print_stat("Format errors", report_data['parse_errors'])

        success_rate = (report_data['parsed_lines'] / report_data['total_lines'] * 100) if report_data['total_lines'] > 0 else 0
        self._print_stat("Parse success rate", f"{success_rate:.2f}%")

        # Detection summary
        self._print_header("ATTACK DETECTION SUMMARY", 2)

        total_detections = sum(len(detections) for detections in report_data['detections'].values())

        if total_detections == 0:
            print(f"    {self.colors['GREEN']}✓ No attacks detected in log{self.colors['END']}")
        else:
            for attack_type, detections in sorted(report_data['detections'].items()):
                if detections:
                    color = self.colors['RED'] if len(detections) > 10 else self.colors['YELLOW']
                    print(f"    {color}• {attack_type}: {len(detections)} detections{self.colors['END']}")

        # Details by attack type
        self._generate_sql_injection_details(report_data)
        self._generate_xss_details(report_data)
        self._generate_directory_traversal_details(report_data)
        self._generate_brute_force_details(report_data)
        self._generate_ddos_details(report_data)
        self._generate_bot_details(report_data)

        # Recommendations
        self._generate_recommendations(report_data)

        # IP blocking list
        self._generate_blocking_list(report_data)

    def _generate_sql_injection_details(self, report_data: Dict):
        """Generate SQL Injection details"""
        detections = report_data['detections'].get('SQL_INJECTION', [])
        if not detections:
            return

        self._print_header(f"SQL INJECTION - {len(detections)} detections", 2)

        # Top IPs
        ip_counts = Counter(d['ip'] for d in detections)
        print("    Top 5 attacking IPs:")
        for ip, count in ip_counts.most_common(5):
            print(f"      {self.colors['RED']}- {ip}: {count} attempts{self.colors['END']}")

        # Examples
        print("\n    Detected payload examples:")
        for detection in detections[:3]:
            print(f"      Line {detection.get('line_number', 'N/A')}: {detection['ip']}")
            print(f"        Path: {detection['path'][:80]}")

    def _generate_xss_details(self, report_data: Dict):
        """Generate XSS details"""
        detections = report_data['detections'].get('XSS', [])
        if not detections:
            return

        self._print_header(f"XSS - {len(detections)} detections", 2)

        ip_counts = Counter(d['ip'] for d in detections)
        print("    Top 5 attacking IPs:")
        for ip, count in ip_counts.most_common(5):
            print(f"      {self.colors['RED']}- {ip}: {count} attempts{self.colors['END']}")

    def _generate_directory_traversal_details(self, report_data: Dict):
        """Generate Directory Traversal details"""
        detections = report_data['detections'].get('DIRECTORY_TRAVERSAL', [])
        if not detections:
            return

        self._print_header(f"DIRECTORY TRAVERSAL - {len(detections)} detections", 2)

        # Top IPs
        ip_counts = Counter(d['ip'] for d in detections)
        print("    Top 5 attacking IPs:")
        for ip, count in ip_counts.most_common(5):
            print(f"      {self.colors['RED']}- {ip}: {count} attempts{self.colors['END']}")

        # Target files
        targets = Counter(d.get('target_file', 'Unknown') for d in detections)
        print("\n    Most common target files:")
        for target, count in targets.most_common(5):
            print(f"      - {target}: {count} attempts")

    def _generate_brute_force_details(self, report_data: Dict):
        """Generate Brute Force details"""
        detections = report_data['detections'].get('BRUTE_FORCE', [])
        stats = report_data['statistics'].get('BRUTE_FORCE', {})

        if not detections and not stats.get('top_attacking_ips'):
            return

        self._print_header(f"BRUTE FORCE - Attempt analysis", 2)

        if stats.get('top_attacking_ips'):
            print("    IPs with most failed attempts:")
            for ip, count in list(stats['top_attacking_ips'].items())[:10]:
                color = self.colors['RED'] if count > 50 else self.colors['YELLOW']
                print(f"      {color}- {ip}: {count} failed attempts{self.colors['END']}")

        # Detection subtypes
        subtypes = Counter(d.get('subtype', 'UNKNOWN') for d in detections)
        if subtypes:
            print("\n    Detection types:")
            for subtype, count in subtypes.items():
                print(f"      - {subtype}: {count}")

    def _generate_ddos_details(self, report_data: Dict):
        """Generate DDoS details"""
        detections = report_data['detections'].get('DDOS', [])
        stats = report_data['statistics'].get('DDOS', {})

        if not detections and not stats.get('ips_flagged_as_ddos'):
            return

        self._print_header(f"DDoS ANALYSIS", 2)

        if stats:
            self._print_stat("IPs flagged as DDoS", stats.get('ips_flagged_as_ddos', 0))
            self._print_stat("Configured threshold", f"{stats.get('threshold', 100)} req/{stats.get('time_window', 60)}s")

            if stats.get('top_requesters'):
                print("\n    Top 10 IPs by request volume:")
                for ip, count in list(stats['top_requesters'].items())[:10]:
                    color = self.colors['RED'] if count > stats.get('threshold', 100) else self.colors['YELLOW']
                    print(f"      {color}- {ip}: {count} requests{self.colors['END']}")

    def _generate_bot_details(self, report_data: Dict):
        """Generate Bot details"""
        detections = report_data['detections'].get('MALICIOUS_BOT', [])
        if not detections:
            return

        self._print_header(f"MALICIOUS BOTS - {len(detections)} detections", 2)

        # Bot types
        bot_types = Counter(d.get('subtype', 'UNKNOWN') for d in detections)
        print("    Detected bot types:")
        for bot_type, count in bot_types.most_common():
            print(f"      {self.colors['YELLOW']}- {bot_type}: {count}{self.colors['END']}")

        # Unique user agents
        user_agents = Counter(d['user_agent'] for d in detections if d['user_agent'])
        print(f"\n    Unique malicious User Agents: {len(user_agents)}")

        if user_agents:
            print("    Top 5 User Agents:")
            for ua, count in user_agents.most_common(5):
                print(f"      - {ua[:60]}: {count} requests")

    def _generate_recommendations(self, report_data: Dict):
        """Generate security recommendations"""
        self._print_header("SECURITY RECOMMENDATIONS", 1)

        recommendations = []

        if report_data['detections'].get('SQL_INJECTION'):
            recommendations.extend([
                "• Implement input validation and use prepared statements",
                "• Configure a Web Application Firewall (WAF)",
                "• Apply least privilege principle to database"
            ])

        if report_data['detections'].get('XSS'):
            recommendations.extend([
                "• Implement Content Security Policy (CSP)",
                "• Sanitize all user inputs",
                "• Use appropriate output encoding"
            ])

        if report_data['detections'].get('DIRECTORY_TRAVERSAL'):
            recommendations.extend([
                "• Validate and sanitize file paths",
                "• Configure proper server permissions",
                "• Use chroot jail for critical applications"
            ])

        if report_data['detections'].get('DDOS'):
            recommendations.extend([
                "• Implement rate limiting",
                "• Consider DDoS protection service (Cloudflare, AWS Shield)",
                "• Configure connection limits in web server"
            ])

        if report_data['detections'].get('BRUTE_FORCE'):
            recommendations.extend([
                "• Implement fail2ban or similar",
                "• Use two-factor authentication",
                "• Implement CAPTCHA after failed attempts"
            ])

        if report_data['detections'].get('MALICIOUS_BOT'):
            recommendations.extend([
                "• Implement User-Agent verification",
                "• Use robots.txt properly",
                "• Consider implementing JavaScript challenges"
            ])

        if recommendations:
            # Remove duplicates while maintaining order
            seen = set()
            unique_recommendations = []
            for rec in recommendations:
                if rec not in seen:
                    seen.add(rec)
                    unique_recommendations.append(rec)

            for rec in unique_recommendations:
                print(f"    {self.colors['GREEN']}{rec}{self.colors['END']}")
        else:
            print(f"    {self.colors['GREEN']}✓ No immediate actions required{self.colors['END']}")

    def _generate_blocking_list(self, report_data: Dict):
        """Generate IP blocking recommendations"""
        # Collect all attacking IPs
        all_attacking_ips = defaultdict(int)

        for attack_type, detections in report_data['detections'].items():
            for detection in detections:
                all_attacking_ips[detection['ip']] += 1

        if not all_attacking_ips:
            return

        self._print_header("RECOMMENDED IPS FOR BLOCKING", 2)

        print(f"    Total unique attacking IPs: {len(all_attacking_ips)}")
        print(f"\n    {self.colors['RED']}Top 20 most aggressive IPs:{self.colors['END']}")

        for ip, count in sorted(all_attacking_ips.items(), key=lambda x: x[1], reverse=True)[:20]:
            severity = "CRITICAL" if count > 50 else "HIGH" if count > 20 else "MEDIUM"
            color = self.colors['RED'] if count > 50 else self.colors['YELLOW']
            print(f"      {color}{ip}: {count} total attacks [{severity}]{self.colors['END']}")

        # Generate example iptables command
        print(f"\n    {self.colors['BLUE']}Example iptables blocking:{self.colors['END']}")
        top_ip = sorted(all_attacking_ips.items(), key=lambda x: x[1], reverse=True)[0][0]
        print(f"      sudo iptables -A INPUT -s {top_ip} -j DROP")

        print(f"\n    {self.colors['BLUE']}To block all detected IPs:{self.colors['END']}")
        print("      for ip in $(cat attacking_ips.txt); do")
        print("          sudo iptables -A INPUT -s $ip -j DROP")
        print("      done")