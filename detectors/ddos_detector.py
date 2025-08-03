"""
detectors/ddos_detector.py - DDoS attack detector
"""

from typing import Dict, Optional, List
from collections import defaultdict
from datetime import datetime
from detectors.base_detector import BaseDetector

class DdosDetector(BaseDetector):
    """Detector specialized in DDoS attacks"""

    def __init__(self, threshold: int = 100, time_window: int = 60):
        super().__init__()
        self.name = "DDOS"
        self.threshold = threshold
        self.time_window = time_window  # seconds

        # Request tracking per IP
        self.ip_requests = defaultdict(list)
        self.ip_flagged = set()  # IPs already marked as DDoS

    def _parse_timestamp(self, timestamp_str: str) -> Optional[float]:
        """Convert Apache timestamp to Unix timestamp"""
        try:
            # Typical format: 10/Oct/2024:13:55:36 +0000
            dt = datetime.strptime(timestamp_str.split()[0], '%d/%b/%Y:%H:%M:%S')
            return dt.timestamp()
        except:
            return None

    def analyze(self, log_entry: Dict) -> Optional[Dict]:
        """Detect possible DDoS attacks"""

        ip = log_entry['ip']
        timestamp_str = log_entry['timestamp']

        # Parse timestamp
        timestamp = self._parse_timestamp(timestamp_str)
        if not timestamp:
            return None

        # Add request to tracking
        self.ip_requests[ip].append(timestamp)

        # Clean old requests (outside time window)
        current_window_start = timestamp - self.time_window
        self.ip_requests[ip] = [ts for ts in self.ip_requests[ip]
                               if ts >= current_window_start]

        # Check if threshold is exceeded
        request_count = len(self.ip_requests[ip])

        if request_count >= self.threshold:
            # Only report first detection
            if ip not in self.ip_flagged:
                self.ip_flagged.add(ip)
                return {
                    'type': self.name,
                    'ip': ip,
                    'timestamp': log_entry['timestamp'],
                    'method': log_entry['method'],
                    'path': log_entry['path'],
                    'status': log_entry['status'],
                    'user_agent': log_entry['user_agent'],
                    'requests_in_window': request_count,
                    'time_window': self.time_window,
                    'line_number': log_entry.get('line_number', 0)
                }

        return None

    def get_statistics(self) -> Dict:
        """Return detector statistics"""
        # Calculate statistics per IP
        ip_stats = {}
        for ip, requests in self.ip_requests.items():
            if requests:
                ip_stats[ip] = {
                    'total_requests': len(requests),
                    'flagged_as_ddos': ip in self.ip_flagged
                }

        return {
            'total_ips_tracked': len(self.ip_requests),
            'ips_flagged_as_ddos': len(self.ip_flagged),
            'threshold': self.threshold,
            'time_window': self.time_window,
            'top_requesters': dict(sorted(
                [(ip, len(reqs)) for ip, reqs in self.ip_requests.items()],
                key=lambda x: x[1],
                reverse=True
            )[:10])
        }