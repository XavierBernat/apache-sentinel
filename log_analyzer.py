"""
log_analyzer.py - Main analysis coordinator
"""

from typing import Dict, List
from collections import defaultdict

from log_parser import ApacheLogParser
from detectors.sql_injection_detector import SqlInjectionDetector
from detectors.xss_detector import XssDetector
from detectors.directory_traversal_detector import DirectoryTraversalDetector
from detectors.brute_force_detector import BruteForceDetector
from detectors.ddos_detector import DdosDetector
from detectors.bot_detector import BotDetector
from reporters.base_reporter import BaseReporter

class LogAnalyzer:
    """Main coordinator that orchestrates log analysis"""

    def __init__(self, config: Dict, reporter: BaseReporter):
        self.config = config
        self.reporter = reporter
        self.parser = ApacheLogParser()

        # General statistics
        self.total_lines = 0
        self.parsed_lines = 0
        self.parse_errors = 0

        # Detection results
        self.detection_results = defaultdict(list)

        # Initialize detectors
        self.detectors = [
            SqlInjectionDetector(),
            XssDetector(),
            DirectoryTraversalDetector(),
            BruteForceDetector(config.get('brute_force_threshold', 10)),
            DdosDetector(
                config.get('ddos_threshold', 100),
                config.get('time_window', 60)
            ),
            BotDetector()
        ]

    def analyze_file(self, filepath: str):
        """Analyze a complete log file"""
        print(f"\n[*] Analyzing file: {filepath}")
        print("-" * 60)

        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            for line_num, line in enumerate(f, 1):
                self.total_lines += 1

                # Show progress
                if line_num % 10000 == 0:
                    print(f"  Processed {line_num:,} lines...", end='\r')

                # Parse line
                log_entry = self.parser.parse(line.strip())

                if not log_entry:
                    self.parse_errors += 1
                    continue

                self.parsed_lines += 1
                log_entry['line_number'] = line_num

                # Run all detectors
                for detector in self.detectors:
                    detection = detector.analyze(log_entry)
                    if detection:
                        self.detection_results[detector.name].append(detection)

        print(f"\n  ✓ Analysis complete: {self.total_lines:,} lines processed")

    def generate_report(self):
        """Generate report using configured strategy"""
        # Prepare report data
        report_data = {
            'total_lines': self.total_lines,
            'parsed_lines': self.parsed_lines,
            'parse_errors': self.parse_errors,
            'detections': {},
            'statistics': {}
        }

        # Add results from each detector
        for detector in self.detectors:
            detector_results = self.detection_results.get(detector.name, [])
            report_data['detections'][detector.name] = detector_results

            # Get detector-specific statistics
            if hasattr(detector, 'get_statistics'):
                report_data['statistics'][detector.name] = detector.get_statistics()

        # Generate report using selected strategy
        self.reporter.generate(report_data)