"""CLI entrypoint for ContextDuty."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .engine import redact_file, report_to_json, scan_file
from .policy import load_policy, unknown_detector_names, write_default_policy


def _parser() -> argparse.ArgumentParser:
    from . import __version__

    parser = argparse.ArgumentParser(
        prog="contextduty", description="Protect AI context with policy checks."
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    subparsers = parser.add_subparsers(dest="command", required=True)

    init_parser = subparsers.add_parser("init", help="Create default policy file.")
    init_parser.add_argument("--path", default=".contextduty.json", help="Policy output path.")

    scan_parser = subparsers.add_parser("scan", help="Scan a text file for risky data.")
    scan_parser.add_argument("target", help="Input file path.")
    scan_parser.add_argument("--policy", default=".contextduty.json", help="Policy path.")
    scan_parser.add_argument("--report", help="Optional report output JSON path.")

    redact_parser = subparsers.add_parser("redact", help="Redact risky data from an input file.")
    redact_parser.add_argument("--in", dest="input_path", required=True, help="Input file path.")
    redact_parser.add_argument("--out", dest="output_path", required=True, help="Output file path.")
    redact_parser.add_argument("--policy", default=".contextduty.json", help="Policy path.")
    redact_parser.add_argument("--report", help="Optional report output JSON path.")

    policy_parser = subparsers.add_parser("policy", help="Policy operations.")
    policy_subparsers = policy_parser.add_subparsers(dest="policy_command", required=True)
    validate_parser = policy_subparsers.add_parser(
        "validate", help="Validate and resolve a policy file."
    )
    validate_parser.add_argument("--policy", default=".contextduty.json", help="Policy path.")
    validate_parser.add_argument(
        "--strict",
        action="store_true",
        help="Fail validation when unknown detector names are present.",
    )

    return parser


def _load_policy_with_fallback(policy_path: str) -> tuple[Path | None, object]:
    path = Path(policy_path)
    if path.exists():
        return path, load_policy(path)
    return None, load_policy(None)


def main() -> None:
    parser = _parser()
    args = parser.parse_args()

    if args.command == "init":
        out_path = Path(args.path)
        write_default_policy(out_path)
        print(f"Created policy at {out_path}")
        return

    if args.command == "scan":
        policy_ref, policy = _load_policy_with_fallback(args.policy)
        result = scan_file(Path(args.target), policy)
        report = report_to_json(result)
        print(report)
        if args.report:
            Path(args.report).write_text(report + "\n", encoding="utf-8")
            print(f"Saved report to {args.report}")
        if result.blocked:
            print(f"BLOCKED by policy ({policy_ref or 'default'})", file=sys.stderr)
            raise SystemExit(2)
        return

    if args.command == "redact":
        policy_ref, policy = _load_policy_with_fallback(args.policy)
        result = redact_file(Path(args.input_path), Path(args.output_path), policy)
        report = report_to_json(result)
        print(report)
        if args.report:
            Path(args.report).write_text(report + "\n", encoding="utf-8")
            print(f"Saved report to {args.report}")
        if result.blocked:
            print(f"BLOCKED by policy ({policy_ref or 'default'})", file=sys.stderr)
            raise SystemExit(2)
        return

    if args.command == "policy":
        if args.policy_command == "validate":
            policy_path = Path(args.policy)
            if policy_path.exists():
                policy = load_policy(policy_path)
                source = str(policy_path)
            else:
                policy = load_policy(None)
                source = "default"
            payload = {
                "valid": True,
                "source": source,
                "mode": policy.mode,
                "detectors": sorted(policy.detectors),
                "custom_detectors": sorted(policy.custom_detectors.keys()),
            }
            if args.strict:
                unknown = unknown_detector_names(policy)
                if unknown:
                    print(
                        f"Unknown detector names in strict mode: {', '.join(unknown)}",
                        file=sys.stderr,
                    )
                    raise SystemExit(2)
            print(json.dumps(payload, indent=2))
            return
        raise SystemExit(1)

    raise SystemExit(1)


if __name__ == "__main__":
    main()
