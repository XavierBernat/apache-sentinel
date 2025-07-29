"""
detectors/xss_detector.py - XSS attack detector
"""

import re
from typing import Dict, Optional
from detectors.base_detector import BaseDetector

class XssDetector(BaseDetector):
    """Detector specialized in Cross-Site Scripting (XSS) attacks"""

    def __init__(self):
        super().__init__()
        self.name = "XSS"

        # XSS patterns
        self.patterns = [
            # Script tags
            r'(?i)(<script[^>]*>.*?</script>)',
            r'(?i)(<script[^>]*>)',

            # Event handlers
            r'(?i)(on\w+\s*=)',
            r'(?i)(onerror|onload|onclick|onmouseover|onfocus|onblur|onchange|onsubmit)=',

            # JavaScript protocols
            r'(?i)(javascript:|vbscript:|livescript:)',

            # Dangerous HTML tags
            r'(?i)(<iframe|<object|<embed|<applet|<meta|<link|<style)',

            # JavaScript functions
            r'(?i)(alert\(|confirm\(|prompt\(|eval\()',

            # DOM manipulation
            r'(?i)(document\.|window\.|location\.|top\.|parent\.|frames\.|self\.)',

            # URL encoded XSS
            r'(\%3Cscript|\%3Ciframe|\%3Cobject|\%3Cimg|\%3Csvg)',

            # Image tags with JavaScript
            r'(?i)(<img[^>]+src[^>]+javascript:)',
            r'(?i)(<img[^>]+on\w+)',

            # SVG attacks
            r'(?i)(<svg[^>]*on\w+)',
            r'(?i)(<svg[^>]*>)',

            # Data URI XSS
            r'(?i)(data:text/html|data:application/javascript)',

            # Expression and style attacks
            r'(?i)(expression\(|import\s|@import|charset\s*=)',

            # Base64 encoded scripts
            r'(?i)(base64,[A-Za-z0-9+/]+=*)',
        ]

        self.compiled_patterns = [re.compile(pattern) for pattern in self.patterns]

    def analyze(self, log_entry: Dict) -> Optional[Dict]:
        """Detect possible XSS attacks"""

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
                        'payload': match.group(0)[:50] if match.group(0) else '',
                        'line_number': log_entry.get('line_number', 0)
                    }

        return None