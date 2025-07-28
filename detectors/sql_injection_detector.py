"""
detectors/sql_injection_detector.py - SQL Injection attack detector
"""

import re
from typing import Dict, Optional
from detectors.base_detector import BaseDetector

class SqlInjectionDetector(BaseDetector):
    """Detector specialized in SQL Injection attacks"""

    def __init__(self):
        super().__init__()
        self.name = "SQL_INJECTION"

        # SQL Injection patterns
        self.patterns = [
            # SQL keywords with context
            r'(?i)(union|select|insert|update|delete|drop|create|alter|exec|execute|script|javascript|alert|onload|onerror|onclick).*(?:from|into|where|table|database)',

            # SQL characters and operators
            r'(?i)(\'|"|;|--|\bor\b|\band\b|@@|char|nchar|varchar|nvarchar|cast|convert|exec|execute|xp_|sp_)',

            # Union Select specific
            r'(?i)(union\s+select|union\s+all\s+select)',

            # Time-based SQL injection
            r'(?i)(benchmark|sleep|waitfor\s+delay)',

            # Hex encoding
            r'(0x[0-9a-f]+)',

            # URL encoded SQL characters
            r'(\%27|\%22|\%3D|\%3B|\%2D\%2D)',

            # Dangerous SQL functions
            r'(?i)(concat|group_concat|extractvalue|updatexml|load_file|into\s+outfile|into\s+dumpfile)',

            # SQL comments
            r'(/\*|\*/|#--|--\+)',

            # Boolean-based blind SQL injection
            r'(?i)(\s+and\s+\d+\s*=\s*\d+|\s+or\s+\d+\s*=\s*\d+)',

            # System functions
            r'(?i)(version\(\)|database\(\)|user\(\)|system_user\(\)|session_user\(\)|current_user\(\))',
        ]

        self.compiled_patterns = [re.compile(pattern) for pattern in self.patterns]

    def analyze(self, log_entry: Dict) -> Optional[Dict]:
        """Detect possible SQL Injection attacks"""

        # Fields to check
        check_fields = [
            log_entry.get('path', ''),
            log_entry.get('referer', ''),
            log_entry.get('user_agent', '')
        ]

        for field in check_fields:
            if not field:
                continue

            for pattern in self.compiled_patterns:
                match = pattern.search(field)
                if match:
                    return {
                        'type': self.name,
                        'ip': log_entry['ip'],
                        'timestamp': log_entry['timestamp'],
                        'method': log_entry['method'],
                        'path': log_entry['path'],
                        'status': log_entry['status'],
                        'user_agent': log_entry['user_agent'],
                        'matched_pattern': pattern.pattern[:50] + '...',
                        'matched_field': field[:100],
                        'line_number': log_entry.get('line_number', 0)
                    }

        return None