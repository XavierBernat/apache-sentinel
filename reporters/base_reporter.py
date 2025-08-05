"""
reporters/base_reporter.py - Base interface for report strategies
"""

from abc import ABC, abstractmethod
from typing import Dict, Any

class BaseReporter(ABC):
    """
    Abstract base class for implementing different report strategies
    following the Strategy pattern
    """

    @abstractmethod
    def generate(self, report_data: Dict[str, Any]) -> None:
        """
        Generate report with provided data

        Args:
            report_data: Dictionary with all analysis data
                - total_lines: Total lines processed
                - parsed_lines: Lines parsed successfully
                - parse_errors: Lines with errors
                - detections: Dict with detections by type
                - statistics: Dict with statistics by detector
        """
        pass

    @abstractmethod
    def format_detection(self, detection: Dict) -> str:
        """
        Format an individual detection for the report

        Args:
            detection: Dictionary with detection information

        Returns:
            Formatted string with detection information
        """
        pass