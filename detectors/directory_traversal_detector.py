"""
detectors/directory_traversal_detector.py - Directory Traversal detector
"""

import re
from typing import Dict, Optional
from detectors.base_detector import BaseDetector

class DirectoryTraversalDetector(BaseDetector):
    """Detector specialized in Directory Traversal/Path Traversal attacks"""

    def __init__(self):
        super().__init__()
        self.name = "DIRECTORY_TRAVERSAL"

        # Directory Traversal patterns
        self.patterns = [
            # Basic traversal
            r'(\.\./|\.\.\\)',
            r'(\.\./\.\./|\.\.\\\.\.\\)',

            # URL encoded traversal
            r'(\.\.%2f|\.\.%5c|%2e%2e%2f|%2e%2e%5c)',

            # Double URL encoding
            r'(%252e%252e%252f|%252e%252e%255c)',

            # Unicode encoding
            r'(\.\.\u002f|\.\.\u005c)',

            # Sensitive Linux files
            r'(/etc/passwd|/etc/shadow|/etc/hosts|/etc/group)',
            r'(/proc/self/environ|/proc/version|/proc/cmdline)',
            r'(/var/log/|/var/www/|/var/mail/)',
            r'(/root/|/home/\w+/)',

            # Sensitive Windows files
            r'(C:\\|C:/|C:%5C|C:%2F)',
            r'(\\windows\\|/windows/|%5Cwindows%5C|%2Fwindows%2F)',
            r'(\\winnt\\|/winnt/)',
            r'(\\boot\.ini|/boot\.ini)',
            r'(\\windows\\system32\\|/windows/system32/)',

            # PHP wrappers
            r'(php://filter|php://input|php://output)',
            r'(file://|gopher://|dict://|ftp://|tftp://)',
            r'(expect://|phar://|zip://|data://)',

            # Null byte injection
            r'(%00|\\x00|\0)',

            # Common configuration files
            r'(\.htaccess|\.htpasswd|web\.config|httpd\.conf)',
            r'(\.git/|\.svn/|\.env|\.config)',

            # Logs and backups
            r'(access\.log|error\.log|access_log|error_log)',
            r'(\.bak|\.backup|\.old|\.orig|~)',
        ]

        self.compiled_patterns = [re.compile(pattern, re.IGNORECASE) for pattern in self.patterns]

    def analyze(self, log_entry: Dict) -> Optional[Dict]:
        """Detect Directory Traversal attempts"""

        # Primarily check the path
        path = log_entry.get('path', '')

        if not path:
            return None

        for pattern in self.compiled_patterns:
            match = pattern.search(path)
            if match:
                return {
                    'type': self.name,
                    'ip': log_entry['ip'],
                    'timestamp': log_entry['timestamp'],
                    'method': log_entry['method'],
                    'path': log_entry['path'],
                    'status': log_entry['status'],
                    'user_agent': log_entry['user_agent'],
                    'target_file': match.group(0),
                    'matched_pattern': pattern.pattern[:50] + '...',
                    'line_number': log_entry.get('line_number', 0)
                }

        return None