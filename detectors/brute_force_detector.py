"""
detectors/brute_force_detector.py - Brute force attack detector
"""

from typing import Dict, Optional
from collections import defaultdict
from detectors.base_detector import BaseDetector

class BruteForceDetector(BaseDetector):
    """Detector specialized in brute force attacks"""

    def __init__(self, threshold: int = 10):
        super().__init__()
        self.name = "BRUTE_FORCE"
        self.threshold = threshold

        # Counters per IP
        self.ip_failed_attempts = defaultdict(int)
        self.ip_attempts_details = defaultdict(list)

        # Common administrative paths
        self.admin_paths = [
            'admin', 'administrator', 'wp-admin', 'wp-login',
            'phpmyadmin', 'manager', 'login', 'signin', 'sign-in',
            'cpanel', 'webmail', '.env', 'config', 'panel',
            'dashboard', 'backend', 'backoffice', 'console',
            'controlpanel', 'adminpanel', 'adminer', 'adminer.php',
            'wp-config', 'xmlrpc.php', 'api/login', 'user/login',
            'admin.php', 'login.php', 'index.php/admin',
            'bitrix', 'joomla', 'drupal', 'magento',
        ]

        # Status codes indicating authentication failure
        self.failure_codes = [401, 403, 404, 405]

    def analyze(self, log_entry: Dict) -> Optional[Dict]:
        """Detect possible brute force attacks"""

        ip = log_entry['ip']
        status = log_entry['status']
        path = log_entry.get('path', '').lower()

        # Check if it's a failed attempt
        is_failed = status in self.failure_codes

        # Check if it's an administrative path
        is_admin_path = any(admin in path for admin in self.admin_paths)

        # Record failed attempt
        if is_failed:
            self.ip_failed_attempts[ip] += 1
            self.ip_attempts_details[ip].append({
                'timestamp': log_entry['timestamp'],
                'path': log_entry['path'],
                'status': status
            })

            # If it's an admin path, consider it immediately
            if is_admin_path:
                return {
                    'type': self.name,
                    'subtype': 'ADMIN_PATH_ATTEMPT',
                    'ip': ip,
                    'timestamp': log_entry['timestamp'],
                    'method': log_entry['method'],
                    'path': log_entry['path'],
                    'status': status,
                    'user_agent': log_entry['user_agent'],
                    'total_failures': self.ip_failed_attempts[ip],
                    'line_number': log_entry.get('line_number', 0)
                }

            # Check if threshold is exceeded
            if self.ip_failed_attempts[ip] >= self.threshold:
                return {
                    'type': self.name,
                    'subtype': 'THRESHOLD_EXCEEDED',
                    'ip': ip,
                    'timestamp': log_entry['timestamp'],
                    'method': log_entry['method'],
                    'path': log_entry['path'],
                    'status': status,
                    'user_agent': log_entry['user_agent'],
                    'total_failures': self.ip_failed_attempts[ip],
                    'line_number': log_entry.get('line_number', 0)
                }

        # Also detect scanning of administrative paths even with 200 status
        elif is_admin_path and status == 200:
            # Could be a successful attempt after brute force
            if self.ip_failed_attempts[ip] > 0:
                return {
                    'type': self.name,
                    'subtype': 'POSSIBLE_SUCCESS',
                    'ip': ip,
                    'timestamp': log_entry['timestamp'],
                    'method': log_entry['method'],
                    'path': log_entry['path'],
                    'status': status,
                    'user_agent': log_entry['user_agent'],
                    'previous_failures': self.ip_failed_attempts[ip],
                    'line_number': log_entry.get('line_number', 0)
                }

        return None

    def get_statistics(self) -> Dict:
        """Return detector statistics"""
        return {
            'total_ips_with_failures': len(self.ip_failed_attempts),
            'ips_exceeding_threshold': sum(1 for count in self.ip_failed_attempts.values()
                                          if count >= self.threshold),
            'top_attacking_ips': dict(sorted(self.ip_failed_attempts.items(),
                                            key=lambda x: x[1],
                                            reverse=True)[:10])
        }