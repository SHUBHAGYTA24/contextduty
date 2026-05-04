"""CLI entrypoint for ContextDuty."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .audit import generate_report, write_audit_entry
from .engine import redact_file, report_to_json, scan_file
from .policy import load_policy, unknown_detector_names, write_default_policy

_AUDIT_LOG_HELP = (
    "Append a structured JSONL audit entry after every scan. "
    "Entries never include matched values — only finding counts and detector names."
)


def _parser() -> argparse.ArgumentParser:
    from . import __version__

    parser = argparse.ArgumentParser(
        prog="contextduty", description="Protect AI context with policy checks."
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    subparsers = parser.add_subparsers(dest="command", required=True)

    # ── init ──────────────────────────────────────────────────────────────────
    init_parser = subparsers.add_parser("init", help="Create default policy file.")
    init_parser.add_argument("--path", default=".contextduty.json", help="Policy output path.")

    # ── scan ──────────────────────────────────────────────────────────────────
    scan_parser = subparsers.add_parser("scan", help="Scan a text file for risky data.")
    scan_parser.add_argument("target", help="Input file path.")
    scan_parser.add_argument("--policy", default=".contextduty.json", help="Policy path.")
    scan_parser.add_argument("--report", help="Optional report output JSON path.")
    scan_parser.add_argument("--audit-log", dest="audit_log", help=_AUDIT_LOG_HELP)

    # ── redact ────────────────────────────────────────────────────────────────
    redact_parser = subparsers.add_parser("redact", help="Redact risky data from an input file.")
    redact_parser.add_argument("--in", dest="input_path", required=True, help="Input file path.")
    redact_parser.add_argument("--out", dest="output_path", required=True, help="Output file path.")
    redact_parser.add_argument("--policy", default=".contextduty.json", help="Policy path.")
    redact_parser.add_argument("--report", help="Optional report output JSON path.")
    redact_parser.add_argument("--audit-log", dest="audit_log", help=_AUDIT_LOG_HELP)

    # ── policy ────────────────────────────────────────────────────────────────
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

    # ── install-hooks ─────────────────────────────────────────────────────────
    hooks_parser = subparsers.add_parser(
        "install-hooks",
        help="Install a git pre-commit hook that scans staged files before every commit.",
    )
    hooks_parser.add_argument(
        "--policy",
        default=".contextduty.json",
        help="Policy path written into the hook script.",
    )
    hooks_parser.add_argument(
        "--audit-log",
        dest="audit_log",
        default="",
        help="Audit log path the hook will append to (optional).",
    )
    hooks_parser.add_argument(
        "--repo",
        default=".",
        help="Path to the git repository root. Defaults to current directory.",
    )

    # ── uninstall-hooks ───────────────────────────────────────────────────────
    uninstall_parser = subparsers.add_parser(
        "uninstall-hooks",
        help="Remove the ContextDuty pre-commit hook.",
    )
    uninstall_parser.add_argument("--repo", default=".", help="Path to the git repository root.")

    # ── report ────────────────────────────────────────────────────────────────
    report_parser = subparsers.add_parser(
        "report",
        help="Summarise an audit log produced with --audit-log.",
    )
    report_parser.add_argument(
        "--audit-log",
        dest="audit_log",
        required=True,
        help="Path to the JSONL audit log file.",
    )
    report_parser.add_argument(
        "--out",
        dest="output_path",
        help="Optional path to write the JSON report. Defaults to stdout.",
    )

    return parser


def _load_policy_with_fallback(policy_path: str) -> tuple[Path | None, object]:
    path = Path(policy_path)
    if path.exists():
        return path, load_policy(path)
    return None, load_policy(None)


def main() -> None:  # noqa: C901
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
        if args.audit_log:
            write_audit_entry(
                operation="scan",
                result=result,
                policy_path=str(policy_ref) if policy_ref else None,
                target=args.target,
                audit_log_path=Path(args.audit_log),
            )
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
        if args.audit_log:
            write_audit_entry(
                operation="redact",
                result=result,
                policy_path=str(policy_ref) if policy_ref else None,
                target=args.input_path,
                audit_log_path=Path(args.audit_log),
            )
        if result.blocked:
            print(f"BLOCKED by policy ({policy_ref or 'default'})", file=sys.stderr)
            raise SystemExit(2)
        return

    if args.command == "install-hooks":
        from .hooks import install_git_hook

        try:
            hook_path = install_git_hook(
                Path(args.repo),
                policy_path=args.policy,
                audit_log=args.audit_log,
            )
            print(f"✓ Pre-commit hook installed at {hook_path}")
            print(f"  Policy : {args.policy}")
            if args.audit_log:
                print(f"  Audit  : {args.audit_log}")
            print("")
            print("Staged files will be scanned before every commit.")
            print("To uninstall: contextduty uninstall-hooks")
        except (FileNotFoundError, RuntimeError) as exc:
            print(f"Error: {exc}", file=sys.stderr)
            raise SystemExit(1) from exc
        return

    if args.command == "uninstall-hooks":
        from .hooks import uninstall_git_hook

        try:
            removed = uninstall_git_hook(Path(args.repo))
            if removed:
                print("✓ ContextDuty pre-commit hook removed.")
            else:
                print("No ContextDuty pre-commit hook found — nothing to remove.")
        except RuntimeError as exc:
            print(f"Error: {exc}", file=sys.stderr)
            raise SystemExit(1) from exc
        return

    if args.command == "report":
        summary = generate_report(Path(args.audit_log))
        output = json.dumps(summary, indent=2)
        if getattr(args, "output_path", None):
            Path(args.output_path).write_text(output + "\n", encoding="utf-8")
            print(f"Report written to {args.output_path}")
        else:
            print(output)
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
                "detector_modes": policy.detector_modes,
                "allow_patterns": dict(policy.allow_patterns),
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
