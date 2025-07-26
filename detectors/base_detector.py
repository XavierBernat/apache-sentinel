"""
detectors/base_detector.py - Base class for all detectors
"""

from abc import ABC, abstractmethod
from typing import Dict, Optional, Any

class BaseDetector(ABC):
    """Abstract base class for all attack detectors"""

    def __init__(self):
        self.name = self.__class__.__name__.replace('Detector', '').upper()

    @abstractmethod
    def analyze(self, log_entry: Dict) -> Optional[Dict]:
        """
        Analyze a log entry for attack patterns

        Args:
            log_entry: Dictionary with parsed log fields

        Returns:
            Dict with detection information or None
        """
        pass

    def get_statistics(self) -> Dict[str, Any]:
        """
        Return detector-specific statistics

        Returns:
            Dict with detector statistics
        """
        return {}