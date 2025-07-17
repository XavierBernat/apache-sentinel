#!/usr/bin/env python3
"""
main.py - Entry point for Apache log analyzer
"""

import argparse
import sys
from pathlib import Path

# Add current directory to path for imports
sys.path.insert(0, str(Path(__file__).parent))

from log_analyzer import LogAnalyzer
from reporters.console_reporter import ConsoleReporter

def main():
    parser = argparse.ArgumentParser(
        description='Modular Apache log analyzer for attack detection'
    )
    parser.add_argument(
        'logfile',
        help='Path to Apache log file'
    )
    parser.add_argument(
        '--brute-threshold',
        type=int,
        default=10,
        help='Threshold for brute force detection (default: 10)'
    )
    parser.add_argument(
        '--ddos-threshold',
        type=int,
        default=100,
        help='Requests per window for DDoS detection (default: 100)'
    )
    parser.add_argument(
        '--time-window',
        type=int,
        default=60,
        help='Time window in seconds for DDoS analysis (default: 60)'
    )
    parser.add_argument(
        '--output',
        choices=['console', 'json', 'csv'],
        default='console',
        help='Report output format (default: console)'
    )

    args = parser.parse_args()

    # Configuration for detectors
    config = {
        'brute_force_threshold': args.brute_threshold,
        'ddos_threshold': args.ddos_threshold,
        'time_window': args.time_window
    }

    # Select reporting strategy
    if args.output == 'console':
        reporter = ConsoleReporter()
    # Future reporters can be added here
    else:
        reporter = ConsoleReporter()

    # Create and run analyzer
    analyzer = LogAnalyzer(config, reporter)

    try:
        # Analyze file
        analyzer.analyze_file(args.logfile)

        # Generate report
        analyzer.generate_report()

    except FileNotFoundError:
        print(f"[!] Error: File not found: {args.logfile}")
        sys.exit(1)
    except Exception as e:
        print(f"[!] Error processing file: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()