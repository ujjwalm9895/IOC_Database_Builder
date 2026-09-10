import argparse
import json
from pathlib import Path

from config import INPUT_FOLDER, OUTPUT_FOLDER
from core.client_report import ClientReportBuilder
from core.scanner import FolderScanner


def parse_args():
    parser = argparse.ArgumentParser(
        description="Generate a JSON client compromise report from stealer log folders."
    )
    parser.add_argument(
        "--input",
        type=Path,
        default=INPUT_FOLDER / "Sample",
        help="Root folder containing stealer case folders (default: data/input/Sample)",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=OUTPUT_FOLDER / "client_report.json",
        help="Output JSON file path",
    )
    parser.add_argument(
        "--email",
        type=str,
        default=None,
        help="Filter report to a single email address",
    )
    parser.add_argument(
        "--domain",
        type=str,
        default=None,
        help="Filter report to emails under a domain (e.g. bfd.com.bd)",
    )
    return parser.parse_args()


def main():
    args = parse_args()

    scanner = FolderScanner(args.input)
    cases = scanner.scan()

    print(f"Scanning {len(cases)} case(s) from {args.input}")

    builder = ClientReportBuilder(output_folder=args.output.parent)
    report = builder.build(
        cases,
        email_filter=args.email.lower() if args.email else None,
        domain_filter=args.domain.lower() if args.domain else None,
    )

    args.output.parent.mkdir(parents=True, exist_ok=True)
    with open(args.output, "w", encoding="utf-8") as handle:
        json.dump(report, handle, indent=2, ensure_ascii=False)

    summary = report["summary"]
    print(f"\nReport saved to: {args.output}")
    print(f"Cases scanned       : {summary['total_cases']}")
    print(f"Unique emails found : {summary['total_unique_emails']}")
    print(f"Total credentials   : {summary['total_credentials']}")
    print(f"Risk breakdown      : {summary['risk_breakdown']}")

    if args.email and args.email.lower() not in report["clients_by_email"]:
        print(f"\nWarning: no data found for email '{args.email}'")


if __name__ == "__main__":
    main()
