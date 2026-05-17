"""
contextduty.cli
~~~~~~~~~~~~~~~
Command-line interface for ContextDuty.

Commands
--------
  contextduty init                        Create .contextduty.json
  contextduty scan <file|dir>             Scan file or directory
  contextduty redact --in <f> --out <f>   Redact file
  contextduty scan-history                Scan git commit history
  contextduty install-hook                Install git pre-push/pre-commit hook
  contextduty uninstall-hook              Remove installed hook
  contextduty policy validate             Validate layered policy
  contextduty audit                       Show audit log summary
  contextduty audit tail                  Show last N audit records
  contextduty audit export --out <file>   Export audit log to CSV
  contextduty --version                   Print version
"""

import argparse
import json
import sys
from pathlib import Path
from typing import Optional

# ---------------------------------------------------------------------------
# Internal imports (relative so they work both installed and editable)
# ---------------------------------------------------------------------------
try:
    from contextduty import audit as _audit
    from contextduty import core
    from contextduty import hooks as _hooks
    from contextduty.detectors import BUILTIN_NAMES
    from contextduty.detectors import DETECTORS_DICT as DETECTORS
    from contextduty.dirscanner import aggregate_report, scan_directory
    from contextduty.githistory import scan_history
except ImportError:
    # Fallback for running as __main__ during development
    import sys as _sys

    _pkg = Path(__file__).parent
    _sys.path.insert(0, str(_pkg.parent))
    from contextduty import audit as _audit
    from contextduty import core
    from contextduty import hooks as _hooks
    from contextduty.detectors import BUILTIN_NAMES
    from contextduty.detectors import DETECTORS_DICT as DETECTORS
    from contextduty.dirscanner import aggregate_report, scan_directory
    from contextduty.githistory import scan_history


try:
    from importlib.metadata import version as _pkg_version

    _VERSION = _pkg_version("contextduty")
except Exception:
    _VERSION = "dev"

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _load_policy(policy_path: Optional[str]):
    path = policy_path or ".contextduty.json"
    return core.load_policy(path)


def _build_detectors(policy):
    """Merge built-in detectors with custom_detectors from policy."""
    import re

    enabled_names = set(policy.get("detectors", list(BUILTIN_NAMES)))
    detectors = {k: v for k, v in DETECTORS.items() if k in enabled_names}
    for name, pattern_str in policy.get("custom_detectors", {}).items():
        try:
            detectors[name] = re.compile(pattern_str, re.MULTILINE)
        except re.error as e:
            print(
                f"[ContextDuty] WARNING: custom detector {name!r} has invalid regex: {e}",
                file=sys.stderr,
            )
    return detectors


def _print_json(data):
    print(json.dumps(data, indent=2, default=str))


def _eprint(msg):
    print(msg, file=sys.stderr)


# ---------------------------------------------------------------------------
# Command handlers
# ---------------------------------------------------------------------------


def cmd_init(args):
    path = args.path or ".contextduty.json"
    if Path(path).exists() and not args.force:
        print(f"Policy file already exists: {path}  (use --force to overwrite)")
        return 0
    default = {
        "mode": "redact",
        "detectors": list(BUILTIN_NAMES),
        "custom_detectors": {},
    }
    Path(path).write_text(json.dumps(default, indent=2) + "\n", encoding="utf-8")
    print(f"Created {path}")
    print(f"Built-in detectors ({len(BUILTIN_NAMES)}): {', '.join(sorted(BUILTIN_NAMES))}")
    return 0


def cmd_scan(args):
    policy = _load_policy(args.policy)
    detectors = _build_detectors(policy)
    target = args.target

    if Path(target).is_dir():
        # Directory scan
        def _scan_fn(text, dets, pol):
            return core.scan_text(text, dets)

        results = scan_directory(target, _scan_fn, detectors, policy)
        report = aggregate_report(results)

        mode = policy.get("mode", "warn")
        if mode == "block" and report["findings_count"] > 0:
            report["blocked"] = True

        _print_json(report)

        if args.report:
            Path(args.report).write_text(json.dumps(report, indent=2), encoding="utf-8")

        _audit.record(
            op="scan",
            source=target,
            policy_mode=mode,
            findings=report.get("detector_counts", {}),
            blocked=report.get("blocked", False),
        )

        if mode == "block" and report["findings_count"] > 0:
            return 2
        return 0

    else:
        # Single file scan
        try:
            text = Path(target).read_text(encoding="utf-8", errors="replace")
        except FileNotFoundError:
            _eprint(f"File not found: {target}")
            return 1

        report = core.scan_text(text, detectors)
        mode = policy.get("mode", "warn")
        blocked = mode == "block" and report.get("findings_count", 0) > 0
        blocked_by = list(report.get("detector_counts", {}).keys()) if blocked else []
        report["blocked"] = blocked
        report["blocked_by"] = blocked_by
        report["source"] = target

        _print_json(report)

        if args.report:
            Path(args.report).write_text(json.dumps(report, indent=2), encoding="utf-8")

        _audit.record(
            op="scan",
            source=target,
            policy_mode=mode,
            findings=report.get("detector_counts", {}),
            blocked=blocked,
        )

        audit_log = getattr(args, "audit_log", None)
        if audit_log:
            _audit.write_entry(
                audit_log,
                operation="scan",
                source=target,
                findings_count=report.get("findings_count", 0),
                detector_counts=report.get("detector_counts", {}),
                blocked=blocked,
                blocked_by=blocked_by,
            )

        return 2 if blocked else 0


def cmd_redact(args):
    policy = _load_policy(args.policy)
    detectors = _build_detectors(policy)

    try:
        text = Path(args.input).read_text(encoding="utf-8", errors="replace")
    except FileNotFoundError:
        _eprint(f"File not found: {args.input}")
        return 1

    result = core.redact_text(text, detectors)
    Path(args.output).write_text(result["redacted"], encoding="utf-8")

    report = {
        "source": args.input,
        "output": args.output,
        "findings_count": result.get("findings_count", 0),
        "detector_counts": result.get("detector_counts", {}),
        "masked_values_count": result.get("masked_values_count", 0),
        "blocked": False,
    }
    _print_json(report)

    if args.report:
        Path(args.report).write_text(json.dumps(report, indent=2), encoding="utf-8")

    _audit.record(
        op="redact",
        source=args.input,
        policy_mode=policy.get("mode", "redact"),
        findings=report.get("detector_counts", {}),
        blocked=False,
        masked_values_count=report.get("masked_values_count", 0),
    )

    audit_log = getattr(args, "audit_log", None)
    if audit_log:
        _audit.write_entry(
            audit_log,
            operation="redact",
            source=args.input,
            findings_count=report.get("findings_count", 0),
            detector_counts=report.get("detector_counts", {}),
            blocked=False,
        )

    return 0


def cmd_scan_history(args):
    policy = _load_policy(args.policy)
    detectors = _build_detectors(policy)

    print("[ContextDuty] Scanning git history — this may take a moment...", file=sys.stderr)

    report = scan_history(
        detectors=detectors,
        since=args.since,
        max_commits=args.max_commits,
        repo_path=args.repo,
    )

    out = report.to_dict()
    _print_json(out)

    if args.report:
        Path(args.report).write_text(json.dumps(out, indent=2), encoding="utf-8")

    _audit.record(
        op="scan-history",
        source=args.repo,
        policy_mode=policy.get("mode", "warn"),
        findings=report.detector_counts,
        blocked=False,
        extra={"commits_scanned": report.commits_scanned},
    )

    if out["findings_count"] > 0:
        _eprint(
            f"\n[ContextDuty] ⚠️  {out['findings_count']} secret(s) found "
            f"across {len(out['commits_affected'])} commit(s).\n"
            f"  {report.remediation_hint}"
        )
        return 2
    else:
        print(
            f"[ContextDuty] ✓ No secrets found in {report.commits_scanned} commits.",
            file=sys.stderr,
        )
        return 0


def cmd_install_hook(args):
    hook_type = getattr(args, "hook", "pre-commit")
    try:
        path = _hooks.install_hook(hook_type=hook_type, repo=args.repo)
        print(f"[ContextDuty] ✓ Hook installed: {path}")
        print(f"  Scans staged files on every `git {hook_type.replace('-', ' ')}`.")
        print("  To remove: contextduty uninstall-hooks")
        return 0
    except Exception as exc:
        _eprint(f"[ContextDuty] Error installing hook: {exc}")
        return 1


def cmd_install_hooks(args):
    """Install pre-commit hook (plural alias, primary public API)."""
    try:
        path = _hooks.install_git_hook(repo=args.repo)
        print(f"[ContextDuty] ✓ Hook installed: {path}")
        print("  Scans staged files on every `git commit`.")
        print("  To remove: contextduty uninstall-hooks")
        return 0
    except Exception as exc:
        _eprint(f"[ContextDuty] Error installing hook: {exc}")
        return 1


def cmd_uninstall_hook(args):
    hook_type = getattr(args, "hook", "pre-commit")
    try:
        removed = _hooks.uninstall_hook(hook_type=hook_type, repo=args.repo)
        if removed:
            print(f"[ContextDuty] ✓ Hook removed: {hook_type}")
        else:
            print("[ContextDuty] Nothing to remove: no ContextDuty hook found.")
        return 0
    except Exception as exc:
        _eprint(f"[ContextDuty] Error: {exc}")
        return 1


def cmd_uninstall_hooks(args):
    """Remove pre-commit hook (plural alias, primary public API)."""
    try:
        removed = _hooks.uninstall_git_hook(repo=args.repo)
        if removed:
            print("[ContextDuty] ✓ Hook removed.")
        else:
            print("[ContextDuty] Nothing to remove: no ContextDuty hook found.")
        return 0
    except Exception as exc:
        _eprint(f"[ContextDuty] Error: {exc}")
        return 1


def cmd_policy_validate(args):
    try:
        policy = core.load_policy(args.policy or ".contextduty.json")
        import re

        invalid = []
        for name, pat in policy.get("custom_detectors", {}).items():
            try:
                re.compile(pat)
            except re.error as e:
                invalid.append({"detector": name, "error": str(e)})

        unknown = []
        if args.strict:
            for det in policy.get("detectors", []):
                if det not in BUILTIN_NAMES and det not in policy.get("custom_detectors", {}):
                    unknown.append(det)

        result = {
            "valid": not invalid and not unknown,
            "source": args.policy or ".contextduty.json",
            "mode": policy.get("mode"),
            "detectors": policy.get("detectors", []),
            "custom_detectors": list(policy.get("custom_detectors", {}).keys()),
            "invalid_patterns": invalid,
            "unknown_detectors": unknown,
        }
        _print_json(result)
        return 0 if result["valid"] else 1
    except Exception as exc:
        _eprint(f"Policy error: {exc}")
        return 1


def cmd_audit(args):
    if args.audit_cmd == "tail":
        records = _audit.tail(n=args.n)
        _print_json(records)
    elif args.audit_cmd == "export":
        count = _audit.export_csv(args.out)
        print(f"[ContextDuty] Exported {count} records to {args.out}")
    else:
        summary = _audit.summary()
        _print_json(summary)
    return 0


def cmd_report(args):
    """Summarise a custom audit log file written by --audit-log."""
    audit_log = getattr(args, "audit_log", None)
    if not audit_log:
        _eprint("[ContextDuty] --audit-log is required")
        return 1
    data = _audit.read_report(audit_log)
    _print_json(data)
    if args.out:
        Path(args.out).write_text(json.dumps(data, indent=2), encoding="utf-8")
    return 0


# ---------------------------------------------------------------------------
# Parser
# ---------------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="contextduty",
        description="Policy-driven context firewall for AI workflows.",
    )
    parser.add_argument("--version", action="version", version=f"contextduty {_VERSION}")

    sub = parser.add_subparsers(dest="command")

    # init
    p_init = sub.add_parser("init", help="Create .contextduty.json")
    p_init.add_argument("--path", default=None)
    p_init.add_argument("--force", action="store_true")

    # scan
    p_scan = sub.add_parser("scan", help="Scan file or directory")
    p_scan.add_argument("target", help="File or directory to scan")
    p_scan.add_argument("--policy", default=None)
    p_scan.add_argument("--report", default=None, help="Write JSON report to file")
    p_scan.add_argument(
        "--audit-log", default=None, dest="audit_log", help="Append audit entry to file"
    )

    # redact
    p_redact = sub.add_parser("redact", help="Redact sensitive values from a file")
    p_redact.add_argument("--in", dest="input", required=True)
    p_redact.add_argument("--out", dest="output", required=True)
    p_redact.add_argument("--policy", default=None)
    p_redact.add_argument("--report", default=None)
    p_redact.add_argument(
        "--audit-log", default=None, dest="audit_log", help="Append audit entry to file"
    )

    # scan-history
    p_hist = sub.add_parser("scan-history", help="Scan git commit history for secrets")
    p_hist.add_argument("--since", default=None, help="e.g. '6 months ago' or '2024-01-01'")
    p_hist.add_argument("--max-commits", type=int, default=500)
    p_hist.add_argument("--repo", default=".", help="Path to git repo")
    p_hist.add_argument("--policy", default=None)
    p_hist.add_argument("--report", default=None)

    # install-hooks (primary) and install-hook (legacy)
    p_hooks = sub.add_parser("install-hooks", help="Install git pre-commit hook")
    p_hooks.add_argument("--repo", default=".")
    p_hook = sub.add_parser("install-hook", help="Install git hook (legacy alias)")
    p_hook.add_argument("--hook", choices=["pre-commit", "pre-push"], default="pre-commit")
    p_hook.add_argument("--repo", default=".")

    # uninstall-hooks (primary) and uninstall-hook (legacy)
    p_unhooks = sub.add_parser("uninstall-hooks", help="Remove ContextDuty git hook")
    p_unhooks.add_argument("--repo", default=".")
    p_unhook = sub.add_parser("uninstall-hook", help="Remove installed git hook (legacy alias)")
    p_unhook.add_argument("--hook", choices=["pre-commit", "pre-push"], default="pre-commit")
    p_unhook.add_argument("--repo", default=".")

    # policy validate
    p_policy = sub.add_parser("policy", help="Policy management")
    p_policy_sub = p_policy.add_subparsers(dest="policy_cmd")
    p_pv = p_policy_sub.add_parser("validate")
    p_pv.add_argument("--policy", default=None)
    p_pv.add_argument("--strict", action="store_true")

    # audit
    p_audit = sub.add_parser("audit", help="Audit log commands")
    p_audit_sub = p_audit.add_subparsers(dest="audit_cmd")
    p_at = p_audit_sub.add_parser("tail")
    p_at.add_argument("-n", type=int, default=20)
    p_ae = p_audit_sub.add_parser("export")
    p_ae.add_argument("--out", required=True, help="Output CSV path")

    # report
    p_report = sub.add_parser("report", help="Summarise a custom audit log file")
    p_report.add_argument("--audit-log", required=True, dest="audit_log", help="Audit log path")
    p_report.add_argument("--out", default=None, help="Write JSON summary to file")

    return parser


def main():
    parser = build_parser()
    args = parser.parse_args()

    if args.command is None:
        parser.print_help()
        sys.exit(0)

    dispatch = {
        "init": cmd_init,
        "scan": cmd_scan,
        "redact": cmd_redact,
        "scan-history": cmd_scan_history,
        "install-hooks": cmd_install_hooks,
        "uninstall-hooks": cmd_uninstall_hooks,
        "install-hook": cmd_install_hook,
        "uninstall-hook": cmd_uninstall_hook,
        "policy": lambda a: cmd_policy_validate(a) if a.policy_cmd == "validate" else 1,
        "audit": cmd_audit,
        "report": cmd_report,
    }

    handler = dispatch.get(args.command)
    if handler is None:
        parser.print_help()
        sys.exit(1)

    sys.exit(handler(args))


if __name__ == "__main__":
    main()
