"""SENTINEL-IR CLI — everything happens in the terminal; no web dashboard exists.

Sub-commands
  investigate   run the agent on one .eml (the main flow)
  analyze-file  one-shot sandboxed static analysis of an isolated artifact (--confirm required)
  chain         verify / anchor / export the evidence ledger, or deploy the testnet contract
  pixel-listen  optional local listener for the tracking-pixel fallback (3d)
  mock-apis     offline demo/CI server: GeoIP + reputation fixtures on localhost
  selftest      import + registry + ledger smoke test (what a judge can run in 2s)
"""
from __future__ import annotations

import argparse
import json
import os
import shlex
import sys
from pathlib import Path
from typing import Any

from .config import REPO_ROOT, load_config


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(
        prog="sentinel",
        description="Local AI email-threat forensics agent: headers → origin → geo → sandbox → blockchain ledger.",
        epilog="Safety: whitelisted tools only · 15s hard timeout · human gate for file access · press 'x' to abort",
    )
    sub = ap.add_subparsers(dest="cmd", required=True)

    inv = sub.add_parser("investigate", help="investigate a single .eml file end-to-end")
    inv.add_argument("eml", help="path to the .eml evidence file")
    inv.add_argument("--model", help="Ollama model (default llama3.1:8b; env SENTINEL_MODEL)")
    inv.add_argument("--demo", action="store_true", help="non-interactive UI, auto-approve gates (audit-logged)")
    inv.add_argument("--yes", action="store_true", help="auto-approve [CONFIRM_NEEDED] gates")
    inv.add_argument("--no-llm", action="store_true", help="force the deterministic engine (no Ollama)")
    inv.add_argument("--offline", action="store_true", help="no outbound HTTP at all (DNS checks still allowed)")
    inv.add_argument("--timeout", type=float, help="hard per-tool timeout seconds (default 15)")
    inv.add_argument("--steps", type=int, help="max agent loop iterations (default 14)")
    inv.add_argument("--sandbox", choices=["auto", "require", "allow-local"], default="auto",
                     help="auto: docker if present, else labelled subprocess; require: refuse without docker; allow-local: same as auto")
    inv.add_argument("--no-pixel", action="store_true", help="do not offer the tracking-pixel reply draft")
    inv.add_argument("--extra-ioc-file", help="JSONL of captured pixel hits / operator IOCs to fold into the case")
    inv.add_argument("--geo-base-url", help="redirect GeoIP calls (mock-apis server / proxy)")
    inv.add_argument("--reputation-base-url", help="redirect reputation API calls")
    inv.add_argument("--geoip-allow-private", action="store_true",
                     help="allow lookups for loopback/RFC5737 demo IPs (demo corpus only)")
    inv.add_argument("--chain-backend", choices=["auto", "hashchain", "ganache"], help="evidence log backend")
    inv.add_argument("--no-chain", action="store_true", help="skip ledger writes (not recommended)")
    inv.add_argument("--kill-key", help="kill-switch key (default 'x')")
    inv.add_argument("--json", action="store_true", help="print a machine-readable summary at the end")

    af = sub.add_parser("analyze-file", help="sandboxed static analysis of ONE isolated artifact")
    af.add_argument("path", help="path to the suspect file")
    af.add_argument("--confirm", action="store_true", help="required acknowledgement that you are authorized to analyze this file")
    af.add_argument("--offline", action="store_true")
    af.add_argument("--sandbox", choices=["auto", "require"], default="auto")

    ch = sub.add_parser("chain", help="evidence ledger: verify | anchor | export | deploy | record | read")
    ch.add_argument("action", choices=["verify", "anchor", "export", "deploy", "record", "read"])
    ch.add_argument("--path", help="ledger file (default evidence/hashchain.jsonl)")
    ch.add_argument("--json", action="store_true")
    ch.add_argument("--case", help="for 'record': an existing runs/<case>/run.json to (re-)anchor")
    ch.add_argument("--contract", help="for 'deploy'/'record'/'read'/'export --bundle': deployed "
                                       "EvidenceChain address (default: $SENTINEL_CONTRACT_ADDRESS, then the "
                                       "address cached by `chain deploy`)")
    ch.add_argument("--bundle", metavar="OUT.json", help="for 'export': write a third-party verification bundle")
    ch.add_argument("--cases", action="append", metavar="DIR", help="case dir(s) to include in --bundle (repeatable)")
    ch.add_argument("--rpc-url", help="JSON-RPC endpoint (default: $GANACHE_RPC_URL)")
    ch.add_argument("--seq", type=int, help="for 'read': evidence sequence index to fetch from the contract")

    px = sub.add_parser("pixel-listen", help="local listener for the optional tracking-pixel fallback")
    px.add_argument("--port", type=int, default=8099)
    px.add_argument("--bind", default="127.0.0.1", help="0.0.0.0 only if you really intend to receive external hits")
    px.add_argument("--out", default="runs/pixel_hits.jsonl")
    px.add_argument("--record-any", action="store_true",
                    help="also log GETs that are not /open/<case>.gif (debugging only — noisy)")

    ma = sub.add_parser("mock-apis", help="offline GeoIP/reputation fixture server (demo/CI)")
    ma.add_argument("--port", type=int, default=8099)
    ma.add_argument("--bind", default="127.0.0.1")
    ma.add_argument("--fixtures", help="JSON file of canned responses keyed by path")

    sub.add_parser("selftest", help="import/registry/ledger smoke test")
    return ap


# ─────────────────────────────────────────────────────────────────────────────
def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.cmd == "investigate":
        return cmd_investigate(args)
    if args.cmd == "analyze-file":
        return cmd_analyze_file(args)
    if args.cmd == "chain":
        return cmd_chain(args)
    if args.cmd == "pixel-listen":
        return cmd_pixel(args)
    if args.cmd == "mock-apis":
        return cmd_mock(args)
    if args.cmd == "selftest":
        return cmd_selftest()
    return 2


def cmd_investigate(args: argparse.Namespace) -> int:
    from .agent import Agent

    overrides: dict[str, Any] = {}
    if args.timeout:
        overrides["tool_timeout_s"] = args.timeout
    if args.steps:
        overrides["max_agent_steps"] = args.steps
    if args.sandbox == "require":
        overrides["sandbox_required"] = True
    if args.chain_backend:
        overrides["blockchain_backend"] = "hashchain" if args.no_chain else args.chain_backend
    if args.no_chain:
        overrides["blockchain_backend"] = "hashchain"
    if args.extra_ioc_file:
        overrides["extra_ioc_file"] = args.extra_ioc_file

    agent = Agent(
        args.eml, demo=args.demo, auto_confirm=bool(args.yes), offline=args.offline,
        model=args.model, no_llm=args.no_llm, no_pixel=args.no_pixel,
        geo_base_url=args.geo_base_url, reputation_base_url=args.reputation_base_url,
        geoip_allow_private=bool(args.geoip_allow_private) or None,
        extra_ioc_file=args.extra_ioc_file, kill_key=args.kill_key,
        sandbox_required=overrides.get("sandbox_required"),
    )
    agent.cfg.tool_timeout_s = overrides.get("tool_timeout_s", agent.cfg.tool_timeout_s)
    agent.cfg.max_agent_steps = overrides.get("max_agent_steps", agent.cfg.max_agent_steps)
    if args.no_chain:
        agent.cfg.blockchain_backend = "hashchain"
        agent._log_to_chain = lambda verdict, sha: {"file": "(disabled via --no-chain)", "payload": {}}  # type: ignore[assignment]
    try:
        verdict = agent.run()
    except KeyboardInterrupt:
        agent.switch.abort("KeyboardInterrupt")
        print("\n[sentinel] aborted by operator; partial artifacts remain in runs/", file=sys.stderr)
        return 130
    finally:
        agent.close()
    if args.json:
        print(json.dumps({k: verdict.get(k) for k in ("verdict", "confidence", "risk", "sha256", "report",
                                                        "origin_source_kind", "geolocation_summary", "elapsed_s")},
                         indent=2, default=str))
    code = {"MALICIOUS": 2, "SUSPICIOUS": 1, "SAFE": 0}.get(str(verdict.get("verdict")), 1)
    return code


def cmd_analyze_file(args: argparse.Namespace) -> int:
    if not args.confirm:
        print("[sentinel] refusing: --confirm is required (you must assert you are authorized to handle this file)", file=sys.stderr)
        return 2
    from tempfile import mkdtemp

    from .evidence.hasher import digest_file
    from .sandbox import docker_runner

    path = Path(args.path).expanduser().resolve()
    if not path.exists():
        print(f"[sentinel] no such file: {path}", file=sys.stderr)
        return 2
    sha, md5, size = digest_file(path)
    print(f"[sentinel] artifact {path.name}  size={size}  sha256={sha}")
    print("[sentinel] isolation probe:", docker_runner.docker_available()[1])
    work = Path(mkdtemp(prefix="sentinel-onetime-"))
    try:
        run = docker_runner.scan_file(load_config(offline=args.offline, sandbox_required=args.sandbox == "require"),
                                      work, path.name, path)
        print(f"[sentinel] mode={run.mode}")
        print(json.dumps(run.report, indent=2, default=str)[:6000])
        return 0 if run.ok else 1
    finally:
        docker_runner.cleanup_workdir(work)


def cmd_chain(args: argparse.Namespace) -> int:
    from .blockchain.hashchain import HashChain

    cfg = load_config()
    chain = HashChain(args.path or cfg.evidence_chain_path, cfg.head_pointer_path)
    if args.action == "verify":
        rep = chain.verify()
        mark = "✅" if rep.ok else "❌"
        print(f"{mark} evidence chain: {rep.blocks} block(s), head {rep.head_hash[:16] or '—'}…")
        for r in rep.reasons:
            print(f"   · {r}")
        if rep.broken_at is not None:
            print(f"   first broken index: {rep.broken_at}")
        return 0 if rep.ok else 1
    if args.action == "anchor":
        head = chain.head()
        if head is None:
            print("chain is empty — nothing to anchor")
            return 1
        print(json.dumps({"head_index": head.index, "head_hash": head.block_hash,
                          "timestamp": head.timestamp,
                          "how_to_use": "commit this hash somewhere public/append-only (git tag, RFC3161 TSA, or a public chain)",
                          "verify_command": "python -m cybersecurity_agent chain verify"}, indent=2))
        return 0
    if args.action == "export":
        if args.bundle:
            # A verification bundle is only meaningful for cases that were logged; we
            # take the case dirs the operator points at (never a blind glob of everything).
            from .blockchain.ganache_logger import export_verification_bundle

            dirs = [Path(d) for d in (args.cases or [])]
            missing = [str(d) for d in dirs if not (d / "run.json").exists()]
            if not dirs:
                print("usage: chain export --bundle OUT.json --cases runs/<case> [--cases ...] [--rpc-url URL]", file=sys.stderr)
                return 2
            if missing:
                print(f"[sentinel] skipped (no run.json): {', '.join(missing)}", file=sys.stderr)
            info = export_verification_bundle([d for d in dirs if d not in missing], out_path=Path(args.bundle),
                                              chain_path=Path(args.path or cfg.evidence_chain_path),
                                              head_path=cfg.head_pointer_path, rpc_url=args.rpc_url,
                                              contract=args.contract)
            print(json.dumps({k: info[k] for k in ("bundle_path", "case_count", "ledger") if k in info},
                             indent=2, default=str))
            return 0
        print(json.dumps(chain.export(), indent=2, default=str))
        return 0
    if args.action == "read":
        from .blockchain.ganache_logger import GanacheError, GanacheLogger, ping

        if args.seq is None:
            print("chain read --seq N [--contract 0x…] [--rpc-url URL]", file=sys.stderr)
            return 2
        url = args.rpc_url or cfg.ganache_rpc_url
        ok, note, _ = ping(url)
        if not ok:
            print(f"[sentinel] no node at {url}: {note}", file=sys.stderr)
            return 1
        try:
            lg = GanacheLogger(url, contract=args.contract)
            print(json.dumps(lg.fetch_record(args.seq), indent=2))
            return 0
        except (GanacheError, ValueError) as exc:
            print(f"[sentinel] read failed: {exc}", file=sys.stderr)
            return 1
    if args.action == "record":
        run_json = Path(args.case) if args.case else Path(".")
        if not run_json.exists():
            print("pass --case runs/<case>/run.json", file=sys.stderr)
            return 2
        blob = json.loads(run_json.read_text(encoding="utf-8"))
        payload = blob.get("chain", {}).get("payload") or {}
        if not payload:
            print("run.json has no chain payload", file=sys.stderr)
            return 2
        block = chain.append(payload)
        print(f"re-anchored case as block {block.index}: {block.block_hash}")
        # Optional: mirror the same payload onto a local testnet so the record survives
        # this disk. If the node/contract is missing we say so and keep the local anchor.
        if args.contract or os.environ.get("SENTINEL_CONTRACT_ADDRESS"):
            from .blockchain.ganache_logger import GanacheError, GanacheLogger, ping

            ok, note, _ = ping(cfg.ganache_rpc_url)
            if not ok:
                print(f"[sentinel] on-chain mirror skipped: no testnet at {cfg.ganache_rpc_url} ({note})")
                return 0
            try:
                lg = GanacheLogger(cfg.ganache_rpc_url, private_key=os.environ.get("SENTINEL_ETH_PRIVATE_KEY"),
                                   contract=args.contract)
                lg.connect()
                rec = lg.log(payload, verdict=str(payload.get("AI_verdict", "")),
                             file_hash=str(payload.get("file_hash", "")),
                             confidence=float(payload.get("confidence_score", 0.0) or 0.0))
                if rec.ok:
                    print(f"[sentinel] on-chain: tx {rec.tx_hash} in block {rec.block_number}")
                else:
                    print(f"[sentinel] on-chain mirror FAILED (local anchor still valid): {rec.error}")
            except GanacheError as exc:
                print("[sentinel] on-chain mirror failed:", exc)
        return 0
    if args.action == "deploy":
        from .blockchain.ganache_logger import GanacheError, GanacheLogger, ping

        ok, note, _ = ping(cfg.ganache_rpc_url)
        if not ok:
            print(f"[sentinel] no local testnet at {cfg.ganache_rpc_url}: {note}")
            print("            start one with:  ganache --wallet.seed 'sentinel'   (or use backend 'hashchain')")
            return 1
        try:
            lg = GanacheLogger(cfg.ganache_rpc_url, private_key=os.environ.get("SENTINEL_ETH_PRIVATE_KEY"),
                               contract=args.contract)
            print("connected:", lg.connect())
            print("contract  :", lg.ensure_contract())
            return 0
        except GanacheError as exc:
            print("[sentinel] deploy failed:", exc)
            print("            compile the artifact first:  ./scripts/compile_contract.sh")
            return 1
    return 2


def cmd_pixel(args: argparse.Namespace) -> int:
    from .tools_dev import serve_pixel

    print(f"[sentinel] pixel listener on http://{args.bind}:{args.port} → appending {args.out}")
    print("[sentinel] embed URL shape: http://HOST:PORT/open/<case-token>.gif   (only hit this from mail you own)")
    serve_pixel(bind=args.bind, port=args.port, out=Path(args.out), record_any=args.record_any)
    return 0


def cmd_mock(args: argparse.Namespace) -> int:
    from .tools_dev import serve_mock

    print(f"[sentinel] mock GeoIP/reputation API on http://{args.bind}:{args.port} (fixtures: {args.fixtures or 'built-in demo set'})")
    print("[sentinel] use with:  --geo-base-url http://127.0.0.1:%d --reputation-base-url http://127.0.0.1:%d --geoip-allow-private"
          % (args.port, args.port))
    serve_mock(bind=args.bind, port=args.port, fixtures=Path(args.fixtures) if args.fixtures else None)
    return 0


def cmd_selftest() -> int:
    from . import tools as T
    from .blockchain.hashchain import HashChain
    from .risk import fuse
    from .safety import run_with_timeout, ToolTimeoutError

    failures: list[str] = []
    names = sorted(T.REGISTRY)
    print(f"registry  : {len(names)} whitelisted tools → {', '.join(names)}")
    for required in ("parse_headers", "resolve_origin", "geolocate_ip", "check_tor_exit",
                     "extract_urls", "check_reputation", "static_file_scan", "hash_evidence"):
        if required not in names:
            failures.append(f"missing tool {required}")
    try:
        T.validate_call("shell", {})
        failures.append("FORBIDDEN_ACTIONS not enforced")
    except T.WhitelistViolation:
        print("whitelist : correctly refuses 'shell' / unknown tools")
    try:
        run_with_timeout(lambda: __import__("time").sleep(2), timeout=0.2, label="selftest")
        failures.append("timeout not enforced")
    except ToolTimeoutError:
        print("timeout   : ToolTimeoutError raised as expected")
    from .risk import RiskSignal  # noqa: F401
    from .models import RiskSignal as RS

    print("fuse      :", fuse([RS("brand_mismatch", 1, 90, source="t"), RS("spf_fail", 1, 80, source="t")]),
          "for brand_mismatch+spf_fail")
    tmp = Path(os.environ.get("TMPDIR", "/tmp")) / "sentinel-selftest-chain.jsonl"
    tmp.unlink(missing_ok=True)
    chain = HashChain(tmp, tmp.with_name("HEAD.json"))
    chain.append({"file_hash": "a" * 64, "AI_verdict": "SAFE", "confidence_score": 70, "timestamp": "t", "geolocation_summary": "x"})
    ok = chain.verify().ok
    txt = tmp.read_text()
    tmp.write_text(txt.replace('"SAFE"', '"MALICIOUS"'))
    tamper = chain.verify()
    tmp.unlink(missing_ok=True)
    print("ledger    :", "append+verify ok" if ok else "FAILED", "| tamper detected:", not tamper.ok)
    if not ok or tamper.ok:
        failures.append("hash-chain behaviour wrong")
    if failures:
        print("FAILURES  :", failures)
        return 1
    print("selftest  : ✅ all safety invariants hold")
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
