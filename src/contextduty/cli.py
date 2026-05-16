"""CLI entrypoint for ContextDuty."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .audit import generate_report, write_audit_entry
from .dashboard import DEFAULT_LOG, DEFAULT_PORT
from .engine import redact_file, report_to_json, scan_dir, scan_file
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

    # dashboard
    dash_parser = subparsers.add_parser(
        "dashboard",
        help="Open the local audit-log dashboard in your browser.",
    )
    dash_parser.add_argument(
        "--audit-log",
        dest="audit_log",
        default=str(DEFAULT_LOG),
        help=f"Path to the JSONL audit log (default: {DEFAULT_LOG}).",
    )
    dash_parser.add_argument(
        "--port",
        type=int,
        default=DEFAULT_PORT,
        help=f"Local port to serve on (default: {DEFAULT_PORT}).",
    )
    dash_parser.add_argument(
        "--demo",
        action="store_true",
        help="Load synthetic demo data even if a real log file exists.",
    )
    dash_parser.add_argument(
        "--no-open",
        dest="no_open",
        action="store_true",
        help="Don't open the browser automatically.",
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

    # ── demo ──────────────────────────────────────────────────────────────────
    subparsers.add_parser(
        "demo",
        help="Run an interactive demo — catches a fake secret in under 20 seconds.",
    )

    # ── protect ───────────────────────────────────────────────────────────────
    protect_parser = subparsers.add_parser(
        "protect",
        help="Universal AI workspace protection — blocks sensitive files from ALL AI tools.",
    )
    protect_sub = protect_parser.add_subparsers(dest="protect_command")

    # protect (no subcommand = setup)
    protect_parser.add_argument("--workspace", default=".", help="Workspace root (default: cwd).")
    protect_parser.add_argument("--policy", default=None, help="Policy file path.")

    # protect watch
    pw = protect_sub.add_parser("watch", help="Watch and auto-update all AI ignore files.")
    pw.add_argument("--workspace", default=".", help="Workspace root.")
    pw.add_argument("--policy", default=None, help="Policy file path.")
    pw.add_argument("--interval", type=int, default=30, help="Scan interval seconds (default: 30).")

    # protect status
    ps_protect = protect_sub.add_parser("status", help="Show protection coverage status.")
    ps_protect.add_argument("--workspace", default=".", help="Workspace root.")

    # ── cursor ────────────────────────────────────────────────────────────────
    cursor_parser = subparsers.add_parser(
        "cursor",
        help="Protect Cursor IDE — block sensitive files from AI indexing.",
    )
    cursor_sub = cursor_parser.add_subparsers(dest="cursor_command", required=True)

    # cursor setup
    cs = cursor_sub.add_parser("setup", help="Scan workspace and generate .cursorignore.")
    cs.add_argument("--workspace", default=".", help="Workspace root (default: current dir).")
    cs.add_argument("--policy", default=None, help="Policy file path.")
    cs.add_argument("--output", default=None, help="Output path (default: <workspace>/.cursorignore).")

    # cursor watch
    cw = cursor_sub.add_parser("watch", help="Watch workspace and auto-update .cursorignore.")
    cw.add_argument("--workspace", default=".", help="Workspace root (default: current dir).")
    cw.add_argument("--policy", default=None, help="Policy file path.")
    cw.add_argument("--interval", type=int, default=30, help="Scan interval in seconds (default: 30).")

    # ── proxy ─────────────────────────────────────────────────────────────────
    proxy_parser = subparsers.add_parser(
        "proxy",
        help="Local HTTPS proxy — intercepts AI API traffic and redacts secrets.",
    )
    proxy_sub = proxy_parser.add_subparsers(dest="proxy_command", required=True)

    # proxy setup
    ps = proxy_sub.add_parser("setup", help="Install CA cert + configure system proxy (one-time).")
    ps.add_argument("--policy", default=".contextduty.json", help="Policy file path.")
    ps.add_argument("--audit-log", dest="audit_log", default="", help="Audit log path.")

    # proxy start
    pst = proxy_sub.add_parser("start", help="Start intercepting AI API traffic.")
    pst.add_argument(
        "--policy", default=None, help="Policy file (default: from setup or .contextduty.json)."
    )
    pst.add_argument("--audit-log", dest="audit_log", default="", help="Audit log path.")
    pst.add_argument("--port", type=int, default=8080, help="Proxy port (default: 8080).")
    pst.add_argument(
        "--set-system-proxy",
        dest="set_system_proxy",
        action="store_true",
        help="Automatically configure macOS system proxy settings.",
    )
    pst.add_argument("--daemon", action="store_true", help="Run in background.")

    # proxy stop
    proxy_sub.add_parser("stop", help="Stop the proxy and restore system settings.")

    # proxy status
    proxy_sub.add_parser("status", help="Show proxy status.")

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
        target = Path(args.target)
        result = scan_dir(target, policy) if target.is_dir() else scan_file(target, policy)
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

    if args.command == "dashboard":
        from .dashboard import serve

        serve(
            audit_log=Path(args.audit_log),
            port=args.port,
            demo=args.demo,
            open_browser=not args.no_open,
        )
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

    if args.command == "demo":
        from .demo import run_demo

        run_demo()
        return

    if args.command == "protect":
        from .protect import protect_status, protect_watch, protect_workspace

        workspace = Path(args.workspace).resolve()
        if args.protect_command == "watch":
            raise SystemExit(protect_watch(workspace, args.policy, args.interval))
        if args.protect_command == "status":
            raise SystemExit(protect_status(workspace))
        # No subcommand = run setup
        raise SystemExit(protect_workspace(workspace, args.policy))

    if args.command == "cursor":
        from .cursor import cursor_setup, cursor_watch

        workspace = Path(args.workspace).resolve()
        if args.cursor_command == "setup":
            output = Path(args.output) if args.output else None
            raise SystemExit(cursor_setup(workspace, args.policy, output))
        if args.cursor_command == "watch":
            raise SystemExit(cursor_watch(workspace, args.policy, args.interval))
        raise SystemExit(1)

    if args.command == "proxy":
        from .proxy import proxy_setup, proxy_start, proxy_status, proxy_stop

        if args.proxy_command == "setup":
            raise SystemExit(proxy_setup(args.policy, args.audit_log))
        if args.proxy_command == "start":
            raise SystemExit(
                proxy_start(
                    policy_path=args.policy,
                    audit_log=args.audit_log,
                    port=args.port,
                    set_system_proxy=args.set_system_proxy,
                    daemon=args.daemon,
                )
            )
        if args.proxy_command == "stop":
            raise SystemExit(proxy_stop())
        if args.proxy_command == "status":
            raise SystemExit(proxy_status())
        raise SystemExit(1)

    raise SystemExit(1)


if __name__ == "__main__":
    main()
