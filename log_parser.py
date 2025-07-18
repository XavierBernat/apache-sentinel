"""
log_parser.py - Apache log parser
"""

import re
from typing import Dict, Optional

class ApacheLogParser:
    """Parser for Apache log files in Common/Combined format"""

    def __init__(self):
        # Combined Log Format (most common)
        self.combined_pattern = re.compile(
            r'^(\S+)\s+'                      # IP
            r'\S+\s+'                          # identd
            r'(\S+)\s+'                        # username
            r'\[([\w:/]+\s[+\-]\d{4})\]\s+'   # timestamp
            r'"(\S+)\s+'                       # method
            r'([^\s"]+)\s*'                    # path
            r'([^"]*)"\s+'                     # protocol
            r'(\d{3})\s+'                      # status
            r'(\S+)\s*'                        # size
            r'"([^"]*)"\s*'                    # referer
            r'"([^"]*)"'                       # user agent
        )

        # Common Log Format
        self.common_pattern = re.compile(
            r'^(\S+)\s+'                      # IP
            r'\S+\s+'                          # identd
            r'(\S+)\s+'                        # username
            r'\[([\w:/]+\s[+\-]\d{4})\]\s+'   # timestamp
            r'"(\S+)\s+'                       # method
            r'([^\s"]+)\s*'                    # path
            r'([^"]*)"\s+'                     # protocol
            r'(\d{3})\s+'                      # status
            r'(\S+)'                           # size
        )

    def parse(self, line: str) -> Optional[Dict]:
        """
        Parse an Apache log line

        Args:
            line: Log line to parse

        Returns:
            Dict with parsed fields or None if parsing fails
        """
        # Try Combined Log Format first
        match = self.combined_pattern.match(line)

        if match:
            groups = match.groups()
            return {
                'ip': groups[0],
                'user': groups[1],
                'timestamp': groups[2],
                'method': groups[3],
                'path': groups[4],
                'protocol': groups[5],
                'status': int(groups[6]),
                'size': groups[7],
                'referer': groups[8],
                'user_agent': groups[9],
                'raw_line': line
            }

        # Try Common Log Format
        match = self.common_pattern.match(line)

        if match:
            groups = match.groups()
            return {
                'ip': groups[0],
                'user': groups[1],
                'timestamp': groups[2],
                'method': groups[3],
                'path': groups[4],
                'protocol': groups[5],
                'status': int(groups[6]),
                'size': groups[7],
                'referer': '',
                'user_agent': '',
                'raw_line': line
            }

        return None