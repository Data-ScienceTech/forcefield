"""ForceField CLI -- selftest, scan, redact, audit, serve, and template validation.

Usage::

    forcefield selftest
    forcefield selftest --verbose
    forcefield scan "Ignore all previous instructions"
    forcefield scan --sensitivity high "some prompt"
    forcefield redact "My SSN is 123-45-6789"
    forcefield audit app.py
    forcefield serve --port 8080
    forcefield validate-template meta-llama/Meta-Llama-3-8B-Instruct
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import time


def _cmd_selftest(args: argparse.Namespace) -> int:
    from .guard import Guard

    guard = Guard(sensitivity=args.sensitivity)
    print(f"ForceField selftest (sensitivity={args.sensitivity})")
    print("-" * 60)

    t0 = time.monotonic()
    result = guard.selftest(verbose=args.verbose)
    elapsed = time.monotonic() - t0

    if args.verbose:
        for r in result.results:
            status = "DETECTED" if r["detected"] else "MISSED"
            print(f"  [{status:8s}] {r['id']:40s}  risk={r['risk_score']:.2f}  {r['prompt'][:50]}")
        print("-" * 60)

    print(f"Total:     {result.total}")
    print(f"Detected:  {result.detected}")
    print(f"Missed:    {result.missed}")
    print(f"Rate:      {result.detection_rate:.1%}")
    print(f"Time:      {elapsed:.2f}s")

    if args.json:
        print(json.dumps({
            "total": result.total,
            "detected": result.detected,
            "missed": result.missed,
            "detection_rate": round(result.detection_rate, 4),
            "elapsed_seconds": round(elapsed, 3),
            "results": result.results,
        }, indent=2))

    return 0 if result.detection_rate >= 0.80 else 1


def _cmd_scan(args: argparse.Namespace) -> int:
    from .guard import Guard

    text = args.text
    if text == "-":
        text = sys.stdin.read()

    guard = Guard(sensitivity=args.sensitivity)
    result = guard.scan(text)

    if args.json:
        print(json.dumps({
            "blocked": result.blocked,
            "action": result.action.value,
            "risk_score": round(result.risk_score, 4),
            "threats": [{"code": t.code, "category": t.category.value, "severity": t.severity} for t in result.threats],
            "rules_triggered": result.rules_triggered,
            "pii_found": [{"type": p.pii_type.value, "confidence": p.confidence} for p in result.pii_found],
            "latency_ms": round(result.latency_ms, 2),
        }, indent=2))
    else:
        status = "BLOCKED" if result.blocked else ("WARN" if result.risk_score > 0 else "CLEAN")
        print(f"Status:     {status}")
        print(f"Risk score: {result.risk_score:.2f}")
        print(f"Action:     {result.action.value}")
        if result.threats:
            print(f"Threats:    {', '.join(t.code for t in result.threats)}")
        if result.pii_found:
            print(f"PII found:  {', '.join(p.pii_type.value for p in result.pii_found)}")
        print(f"Latency:    {result.latency_ms:.1f}ms")

    return 1 if result.blocked else 0


def _cmd_redact(args: argparse.Namespace) -> int:
    from .guard import Guard

    text = args.text
    if text == "-":
        text = sys.stdin.read()

    guard = Guard()
    result = guard.redact(text, strategy=args.strategy)

    if args.json:
        print(json.dumps({
            "text": result.text,
            "pii_found": [{"type": p.pii_type.value, "value": p.value, "confidence": p.confidence} for p in result.pii_found],
            "redaction_count": result.redaction_count,
            "latency_ms": round(result.latency_ms, 2),
        }, indent=2))
    else:
        print(result.text)
        if result.pii_found:
            print(f"\n--- {result.redaction_count} PII item(s) redacted ---")

    return 0


def _cmd_audit(args: argparse.Namespace) -> int:
    from .guard import Guard
    from .pii import detect_pii

    guard = Guard(sensitivity=args.sensitivity)
    _STRING_RE = re.compile(r'(?:f?["\'])((?:[^"\'\\]|\\.){20,})(?:["\'])', re.DOTALL)
    findings: list = []

    def _audit_file(path: str) -> list:
        hits = []
        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
        except OSError:
            return hits
        for i, line in enumerate(content.splitlines(), 1):
            for m in _STRING_RE.finditer(line):
                literal = m.group(1)
                scan = guard.scan(literal)
                pii = detect_pii(literal)
                if scan.risk_score > 0.0 or pii:
                    hits.append({
                        "file": path,
                        "line": i,
                        "risk_score": scan.risk_score,
                        "threats": [t.code for t in scan.threats],
                        "pii": [p.pii_type.value for p in pii],
                        "snippet": literal[:80],
                    })
        return hits

    for p in args.paths:
        if os.path.isfile(p):
            findings.extend(_audit_file(p))
        elif os.path.isdir(p):
            for root, _dirs, files in os.walk(p):
                for fname in files:
                    if fname.endswith(".py"):
                        findings.extend(_audit_file(os.path.join(root, fname)))

    if args.json:
        print(json.dumps({"findings": findings, "total": len(findings)}, indent=2))
    else:
        if not findings:
            print("No issues found.")
        else:
            for f in findings:
                tags = []
                if f["threats"]:
                    tags.append(f"threats={','.join(f['threats'])}")
                if f["pii"]:
                    tags.append(f"pii={','.join(f['pii'])}")
                print(f"  {f['file']}:{f['line']}  risk={f['risk_score']:.2f}  {' '.join(tags)}")
                print(f"    {f['snippet']}")
            print(f"\n{len(findings)} finding(s) in {len(args.paths)} path(s)")

    return 1 if findings else 0


def _cmd_serve(args: argparse.Namespace) -> int:
    try:
        from http.server import HTTPServer, BaseHTTPRequestHandler
    except ImportError:
        print("ERROR: http.server not available", file=sys.stderr)
        return 1

    from .guard import Guard

    guard = Guard(sensitivity=args.sensitivity)

    class _Handler(BaseHTTPRequestHandler):
        def do_POST(self):
            length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(length) if length else b""

            if self.path == "/v1/scan":
                self._handle_scan(body)
            elif self.path == "/v1/redact":
                self._handle_redact(body)
            elif self.path == "/v1/moderate":
                self._handle_moderate(body)
            elif self.path == "/v1/evaluate_tool":
                self._handle_eval_tool(body)
            else:
                self._json_response(404, {"error": "not_found"})

        def do_GET(self):
            if self.path in ("/", "/health", "/healthz"):
                self._json_response(200, {
                    "service": "forcefield-local",
                    "version": "0.2.0",
                    "sensitivity": args.sensitivity,
                })
            else:
                self._json_response(404, {"error": "not_found"})

        def _handle_scan(self, body: bytes):
            try:
                data = json.loads(body)
            except json.JSONDecodeError:
                self._json_response(400, {"error": "invalid_json"})
                return
            text = data.get("text", "")
            if not text and "messages" in data:
                parts = []
                for msg in data["messages"]:
                    if isinstance(msg, dict) and msg.get("role") in ("user", "tool"):
                        c = msg.get("content", "")
                        if isinstance(c, str):
                            parts.append(c)
                text = "\n".join(parts)
            result = guard.scan(text)
            self._json_response(200, {
                "blocked": result.blocked,
                "action": result.action.value,
                "risk_score": result.risk_score,
                "threats": [{"code": t.code, "category": t.category.value, "severity": t.severity} for t in result.threats],
                "rules_triggered": result.rules_triggered,
                "pii_found": [{"type": p.pii_type.value, "confidence": p.confidence} for p in result.pii_found],
                "sanitized_text": result.sanitized_text,
                "latency_ms": round(result.latency_ms, 2),
            })

        def _handle_redact(self, body: bytes):
            try:
                data = json.loads(body)
            except json.JSONDecodeError:
                self._json_response(400, {"error": "invalid_json"})
                return
            text = data.get("text", "")
            strategy = data.get("strategy", "mask")
            result = guard.redact(text, strategy=strategy)
            self._json_response(200, {
                "text": result.text,
                "pii_found": [{"type": p.pii_type.value, "value": p.value} for p in result.pii_found],
                "redaction_count": result.redaction_count,
                "latency_ms": round(result.latency_ms, 2),
            })

        def _handle_moderate(self, body: bytes):
            try:
                data = json.loads(body)
            except json.JSONDecodeError:
                self._json_response(400, {"error": "invalid_json"})
                return
            text = data.get("text", "")
            result = guard.moderate(text, strict=data.get("strict", False))
            self._json_response(200, {
                "passed": result.passed,
                "action": result.action.value,
                "categories": result.categories,
                "flags": result.flags,
                "modified_text": result.modified_text,
            })

        def _handle_eval_tool(self, body: bytes):
            try:
                data = json.loads(body)
            except json.JSONDecodeError:
                self._json_response(400, {"error": "invalid_json"})
                return
            tool_name = data.get("tool_name", "")
            result = guard.evaluate_tool(tool_name)
            self._json_response(200, {
                "allowed": result.allowed,
                "reason": result.reason,
                "tool_name": result.tool_name,
            })

        def _json_response(self, code: int, data: dict):
            body = json.dumps(data).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, fmt, *a):
            status = a[1] if len(a) > 1 else ""
            print(f"  {a[0]}  {status}" if a else fmt)

    server = HTTPServer((args.host, args.port), _Handler)
    print(f"ForceField local proxy (sensitivity={args.sensitivity})")
    print(f"Listening on http://{args.host}:{args.port}")
    print(f"Endpoints: POST /v1/scan, /v1/redact, /v1/moderate, /v1/evaluate_tool")
    print("Press Ctrl+C to stop.\n")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down.")
        server.server_close()
    return 0


def _cmd_test(args: argparse.Namespace) -> int:
    from .endpoint_scanner import scan_endpoint

    url = args.url
    print(f"ForceField endpoint scanner")
    print(f"Target: {url}")
    print(f"Mode:   {args.mode}")
    print("-" * 60)

    def _progress(current: int, total: int, result):
        status = "BLOCKED" if result.blocked else "PASSED"
        print(f"  [{current:3d}/{total}] {status:7s}  {result.attack_id:40s}  {result.latency_ms:.0f}ms")

    report = scan_endpoint(
        url,
        api_key=args.api_key,
        model=args.model,
        mode=args.mode,
        timeout=args.timeout,
        on_progress=_progress if not args.quiet else None,
    )

    print("-" * 60)
    print(f"Total:          {report.total}")
    print(f"Blocked:        {report.blocked}")
    print(f"Passed:         {report.passed}")
    print(f"Errors:         {report.errors}")
    print(f"Detection rate: {report.detection_rate:.1%}")
    print(f"Avg latency:    {report.avg_latency_ms:.0f}ms")
    print(f"Time:           {report.elapsed_seconds:.1f}s")

    # Per-category breakdown
    if report.categories:
        print(f"\nCategory breakdown:")
        for cat, stats in sorted(report.categories.items()):
            rate = stats['blocked'] / stats['total'] if stats['total'] else 0
            print(f"  {cat:35s}  {stats['blocked']}/{stats['total']}  ({rate:.0%})")

    if args.json:
        print("\n" + json.dumps(report.to_dict(), indent=2))

    if args.output:
        with open(args.output, "w") as f:
            json.dump(report.to_dict(), f, indent=2)
        print(f"\nReport saved to {args.output}")

    return 0 if report.detection_rate >= 0.80 else 1


def _cmd_scan_command(args: argparse.Namespace) -> int:
    from .commands import scan_command

    command = args.cmd_text if args.cmd_text != "-" else sys.stdin.read().strip()
    result = scan_command(command)

    if args.json:
        print(json.dumps(result.to_dict(), indent=2))
    else:
        status = "DANGEROUS" if result.dangerous else "SAFE"
        print(f"Command:  {result.command[:80]}")
        print(f"Verdict:  {status}")
        print(f"Severity: {result.severity}")
        if result.findings:
            for f in result.findings:
                print(f"  - [{f.severity.upper():8s}] {f.code}: {f.description}")
        if result.tool_eval and not result.tool_eval.allowed:
            print(f"  - [TOOL    ] {result.tool_eval.tool_name}: {result.tool_eval.reason}")

    return 1 if result.dangerous else 0


def _cmd_scan_filename(args: argparse.Namespace) -> int:
    from .files import scan_filename

    result = scan_filename(args.filename, operation=args.operation)

    if args.json:
        print(json.dumps(result.to_dict(), indent=2))
    else:
        status = "DANGEROUS" if result.dangerous else "SAFE"
        print(f"Filename:  {result.filename}")
        print(f"Operation: {args.operation}")
        print(f"Verdict:   {status}")
        print(f"Severity:  {result.severity}")
        if result.findings:
            for f in result.findings:
                print(f"  - [{f.severity.upper():8s}] {f.code}: {f.description}")

    return 1 if result.dangerous else 0


def _cmd_init(args: argparse.Namespace) -> int:
    import shutil
    from pathlib import Path

    template = args.template
    dest_dir = Path(args.directory)
    dest_file = dest_dir / "constitution.yaml"

    if dest_file.exists() and not args.force:
        print(f"Already exists: {dest_file}")
        print("Use --force to overwrite.")
        return 1

    src = Path(__file__).parent / "constitutions" / f"{template}.yaml"
    if not src.exists():
        print(f"Unknown template: {template}")
        print("Available: default, strict, permissive")
        return 1

    dest_dir.mkdir(parents=True, exist_ok=True)
    shutil.copy2(src, dest_file)

    print(f"Created {dest_file} (template: {template})")
    print()
    print("Next steps:")
    print(f"  1. Review and customize {dest_file}")
    print("  2. In VS Code: install the ForceField extension for real-time Sentinel monitoring")
    print("  3. In Python: Constitution.from_file('.forcefield/constitution.yaml')")
    print("  4. In CI: forcefield selftest && forcefield audit src/")
    return 0


def _cmd_eval(args: argparse.Namespace) -> int:
    from .evals import EvalSuite, run_eval

    if args.builtin:
        cats = args.categories.split(",") if args.categories else None
        suite = EvalSuite.from_builtin(
            name="Built-in Security Eval",
            categories=cats,
            sensitivity=args.sensitivity,
        )
    elif args.suite:
        suite = EvalSuite.from_file(args.suite)
    else:
        print("Error: provide a suite YAML file or --builtin")
        return 1

    print(f"ForceField Eval: {suite.name}")
    print(f"Cases: {len(suite.cases)}  Mode: {suite.target_mode}  Sensitivity: {suite.sensitivity}")
    print("-" * 60)

    def on_progress(current, total, result):
        if args.verbose:
            status = "PASS" if result.passed else "FAIL"
            print(
                f"  [{status:4s}] {result.case_id:40s}  "
                f"risk={result.risk_score:.2f}  {result.expected}->{result.actual}"
            )
            for reason in result.failure_reasons:
                print(f"         {reason}")

    report = run_eval(suite, on_progress=on_progress)

    print("-" * 60)
    print(f"Total:     {report.total}")
    print(f"Passed:    {report.passed_cases}")
    print(f"Failed:    {report.failed_cases}")
    print(f"Rate:      {report.detection_rate:.1%}")
    print(f"Avg lat:   {report.avg_latency_ms:.1f}ms")
    print(f"Time:      {report.elapsed_seconds:.2f}s")
    print(f"Suite:     {'PASSED' if report.suite_passed else 'FAILED'}")

    if report.failure_summary:
        print("\nFailure reasons:")
        for reason in report.failure_summary:
            print(f"  - {reason}")

    if args.json:
        print(report.to_json())

    if args.output:
        with open(args.output, "w") as f:
            f.write(report.to_json())
        print(f"\nReport saved to {args.output}")

    return 0 if report.suite_passed else 1


def _cmd_validate_template(args: argparse.Namespace) -> int:
    from .templates import validate

    print(f"Validating template for: {args.model_id}")
    result = validate(args.model_id)

    if args.json:
        print(json.dumps({
            "verdict": result.verdict,
            "model_id": result.model_id,
            "template_hash": result.template_hash,
            "risk_score": result.risk_score,
            "reason_codes": result.reason_codes,
            "details": result.details,
        }, indent=2))
    else:
        verdict_display = {"pass": "PASS", "warn": "WARN", "fail": "FAIL"}.get(result.verdict, result.verdict.upper())
        print(f"Verdict:    {verdict_display}")
        print(f"Risk score: {result.risk_score:.2f}")
        if result.template_hash:
            print(f"Hash:       {result.template_hash[:16]}...")
        if result.reason_codes:
            print(f"Codes:      {', '.join(result.reason_codes)}")
        if result.details.get("matches"):
            for m in result.details["matches"][:5]:
                print(f"  - [{m['code']}] score={m['score']:.2f}  {m['match'][:60]}")

    return 0 if result.verdict == "pass" else 1


def main(argv: list | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="forcefield",
        description="ForceField AI Security Scanner",
        epilog="Telemetry: ForceField collects anonymous usage statistics (feature counts, SDK version, OS) to improve the product. No prompts, filenames, or PII are ever sent. Disable with FORCEFIELD_NO_TELEMETRY=1 or Guard(telemetry=False). Details: https://datasciencetech.ca/en/python-sdk#telemetry",
    )
    from . import __version__
    parser.add_argument("--version", action="version", version=f"forcefield {__version__}")
    sub = parser.add_subparsers(dest="command")

    # selftest
    p_self = sub.add_parser("selftest", help="Run the built-in 121-attack detection test")
    p_self.add_argument("--sensitivity", default="medium", choices=["low", "medium", "high", "critical"])
    p_self.add_argument("--verbose", "-v", action="store_true")
    p_self.add_argument("--json", action="store_true", help="Output results as JSON")

    # scan
    p_scan = sub.add_parser("scan", help="Scan a prompt for threats")
    p_scan.add_argument("text", help="Text to scan (use '-' for stdin)")
    p_scan.add_argument("--sensitivity", default="medium", choices=["low", "medium", "high", "critical"])
    p_scan.add_argument("--json", action="store_true")

    # redact
    p_redact = sub.add_parser("redact", help="Redact PII from text")
    p_redact.add_argument("text", help="Text to redact (use '-' for stdin)")
    p_redact.add_argument("--strategy", default="mask", choices=["mask", "hash", "remove", "partial", "tokenize"])
    p_redact.add_argument("--json", action="store_true")

    # audit
    p_audit = sub.add_parser("audit", help="Scan Python files for hardcoded prompts and secrets")
    p_audit.add_argument("paths", nargs="+", help="Files or directories to audit")
    p_audit.add_argument("--sensitivity", default="medium", choices=["low", "medium", "high", "critical"])
    p_audit.add_argument("--json", action="store_true")

    # serve
    p_serve = sub.add_parser("serve", help="Start a local ForceField proxy server")
    p_serve.add_argument("--port", type=int, default=8080)
    p_serve.add_argument("--host", default="127.0.0.1")
    p_serve.add_argument("--sensitivity", default="medium", choices=["low", "medium", "high", "critical"])

    # test
    p_test = sub.add_parser("test", help="Run the attack catalog against a live endpoint")
    p_test.add_argument("url", help="Target endpoint URL")
    p_test.add_argument("--api-key", default=None, help="API key for authentication")
    p_test.add_argument("--model", default="gpt-4", help="Model name (for OpenAI-format endpoints)")
    p_test.add_argument("--mode", default="auto", choices=["auto", "openai", "forcefield"])
    p_test.add_argument("--timeout", type=float, default=30.0)
    p_test.add_argument("--json", action="store_true")
    p_test.add_argument("--quiet", "-q", action="store_true", help="Suppress per-attack output")
    p_test.add_argument("--output", "-o", default=None, help="Save JSON report to file")

    # scan-command
    p_cmd = sub.add_parser("scan-command", help="Scan a terminal command for dangerous patterns")
    p_cmd.add_argument("cmd_text", help="Command to scan (use '-' for stdin)")
    p_cmd.add_argument("--json", action="store_true")

    # scan-filename
    p_fn = sub.add_parser("scan-filename", help="Scan a filename for dangerous patterns")
    p_fn.add_argument("filename", help="Filename or path to check")
    p_fn.add_argument("--operation", default="create", choices=["create", "delete", "rename"])
    p_fn.add_argument("--json", action="store_true")

    # eval
    p_eval = sub.add_parser("eval", help="Run a security eval suite")
    p_eval.add_argument("suite", nargs="?", default=None, help="Path to eval suite YAML file")
    p_eval.add_argument("--builtin", action="store_true", help="Run built-in attack eval")
    p_eval.add_argument("--categories", default=None, help="Comma-separated categories (with --builtin)")
    p_eval.add_argument("--sensitivity", default="medium", choices=["low", "medium", "high", "critical"])
    p_eval.add_argument("--verbose", "-v", action="store_true")
    p_eval.add_argument("--json", action="store_true", help="Output results as JSON")
    p_eval.add_argument("--output", "-o", default=None, help="Save JSON report to file")

    # validate-template
    p_tpl = sub.add_parser("validate-template", help="Validate a model's chat template for backdoors")
    p_tpl.add_argument("model_id", help="HuggingFace model ID or local path")
    p_tpl.add_argument("--json", action="store_true")

    # init
    p_init = sub.add_parser("init", help="Scaffold a .forcefield/constitution.yaml for vibe coding governance")
    p_init.add_argument("--template", default="default", choices=["default", "strict", "permissive"],
                         help="Constitution template (default: default)")
    p_init.add_argument("--directory", default=".forcefield", help="Target directory (default: .forcefield)")
    p_init.add_argument("--force", action="store_true", help="Overwrite existing constitution")

    args = parser.parse_args(argv)

    if args.command == "selftest":
        return _cmd_selftest(args)
    elif args.command == "scan":
        return _cmd_scan(args)
    elif args.command == "redact":
        return _cmd_redact(args)
    elif args.command == "audit":
        return _cmd_audit(args)
    elif args.command == "serve":
        return _cmd_serve(args)
    elif args.command == "test":
        return _cmd_test(args)
    elif args.command == "scan-command":
        return _cmd_scan_command(args)
    elif args.command == "scan-filename":
        return _cmd_scan_filename(args)
    elif args.command == "eval":
        return _cmd_eval(args)
    elif args.command == "validate-template":
        return _cmd_validate_template(args)
    elif args.command == "init":
        return _cmd_init(args)
    else:
        parser.print_help()
        return 0


if __name__ == "__main__":
    sys.exit(main())
