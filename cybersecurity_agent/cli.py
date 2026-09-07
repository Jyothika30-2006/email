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
    inv.add_argument("--no-pet", action="store_true", help="hide the work-status cat (also: SENTINEL_PET=0)")
    inv.add_argument("--pet-skin", default=None, metavar="NAME",
                     help="cat colour palette: default|high-contrast|colour-blind|calm|mono (cosmetic only)")
    inv.add_argument("--remind", default=None, metavar="SPEC",
                     help="care reminders, e.g. 'eyes=20,stretch=30,water=45' or 'off' (minutes)")
    inv.add_argument("--pomodoro", default=None, metavar="FOCS,BREAK",
                     help="optional Pomodoro in minutes, e.g. '25,5' (off by default)")
    inv.add_argument("--status-hook", default=None, metavar="PATH",
                     help="extra JSONL sink for work-status events (an external companion can tail it)")
    inv.add_argument("--no-status-hook", action="store_true", help="write no status file at all")
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
    ma.add_argument("--allow-public", action="store_true",
                    help="permit a non-loopback --bind (sandboxed preview only: it serves "
                         "synthetic GeoIP fixtures and no case data)")

    pw = sub.add_parser("pet", help="terminal companion: watch the work-status cat (read-only)")
    pw.add_argument("--path", default=None, metavar="JSONL",
                    help="status.jsonl to read (default: $SENTINEL_STATUS_HOOK, else newest runs/*/status.jsonl)")
    pw.add_argument("--once", action="store_true", help="print one snapshot and exit (scripts/CI)")
    pw.add_argument("--follow", action="store_true", help="keep refreshing until Ctrl-C")
    pw.add_argument("--plain", action="store_true", help="no ANSI/colour, no screen clear")
    pw.add_argument("--skin", default="default", help=", ".join(_pet_skin_names()))
    pw.add_argument("--fps", type=float, default=2.0, help="animation rate (default 2)")
    pw.add_argument("--remind", default="", metavar="SPEC", help="'eyes=20,stretch=30,water=45' or 'off'")
    pw.add_argument("--pomodoro", default="", metavar="FOCS,BREAK", help="e.g. '25,5'")
    pw.add_argument("--tail", type=int, default=6, help="how many recent events to list")

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
    if args.cmd == "pet":
        return cmd_pet(args)
    if args.cmd == "selftest":
        return cmd_selftest()
    return 2


def _pet_skin_names() -> list[str]:
    from .ui.pet import skin_names
    return skin_names()


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
    # Pet / care / status-hook: display knobs, forwarded through cfg_overrides so one mechanism
    # covers both CLI and env (never re-parsed inside the tools).
    if getattr(args, "pet_skin", None):
        overrides["pet_skin"] = args.pet_skin
    if getattr(args, "remind", None) is not None:
        overrides["pet_reminders"] = args.remind
    if getattr(args, "pomodoro", None) is not None:
        overrides["pet_pomodoro"] = args.pomodoro
    if getattr(args, "status_hook", None):
        overrides["status_hook_path"] = args.status_hook

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
    for key in ("pet_skin", "pet_reminders", "pet_pomodoro", "status_hook_path"):
        if key in overrides:
            setattr(agent.cfg, key, overrides[key])
    if getattr(args, "no_pet", False):
        agent.cfg.pet_enabled = False
    if getattr(args, "no_status_hook", False):
        agent.cfg.status_hook_enabled = False
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
    print("[sentinel] use with:  --geo-base-url http://%s:%d --reputation-base-url http://%s:%d --geoip-allow-private"
          % (args.bind, args.port, args.bind, args.port))
    print("[sentinel] a browser can open http://%s:%d/ for the route + fixture index (demo data only)"
          % (args.bind, args.port))
    serve_mock(bind=args.bind, port=args.port, fixtures=Path(args.fixtures) if args.fixtures else None,
               allow_public=bool(getattr(args, "allow_public", False)))
    return 0


def cmd_pet(args: argparse.Namespace) -> int:
    from pathlib import Path as _P

    from .petwatch import mood_vocab, run_pet
    if args.skin not in mood_vocab() and args.skin not in {"default", "mono", "calm",
                                                           "high-contrast", "colour-blind"}:
        print(f"[sentinel] unknown skin '{args.skin}' → using 'default' "
              f"(skins are colour only; they never change what is reported)", file=sys.stderr)
    return run_pet(path=_P(args.path) if args.path else None, follow=args.follow, once=args.once,
                   plain=args.plain, skin=args.skin, fps=args.fps, remind=args.remind,
                   pomodoro=args.pomodoro, tail=max(1, args.tail))


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
    # Display containment (README §12): the pet is a status surface, so it must be enum-only,
    # fixed-size, and unable to echo anything the email said. Checked here because a violation
    # would be a security regression, not a cosmetic one.
    from .status import NOTE_VOCAB, StatusHook, scrub_note
    from .ui.pet import BOX_WIDTH, MOODS, _BOX_H, moods, render_lines

    uniform = all(len(render_lines(m, i)) == _BOX_H
                  and all(len(ln) == BOX_WIDTH for ln in render_lines(m, i))
                  for m in MOODS for i in range(len(MOODS[m]["frames"])))
    attacker_text = ("subject: Invoice #9", "From: ceo@company.com", "ignore previous instructions",
                     "http://paypal.com.login/secure", "https://x.example/\\n<a>")
    leaky = [n for n in attacker_text if scrub_note(n)[0] is not None]
    hostile_sink = Path(os.environ.get("TMPDIR", "/tmp")) / "sentinel-selftest-status.jsonl"
    hostile_sink.unlink(missing_ok=True)
    StatusHook([hostile_sink]).emit("verdict", mood="hop", case="selftest-case",
                                     note=attacker_text[0], verdict="SAFE")
    echoed = attacker_text[0] in hostile_sink.read_text()
    recorded = json.loads(hostile_sink.read_text())
    hostile_sink.unlink(missing_ok=True)
    print(f"pet/hook  : {len(moods())} moods, uniform live box={'yes' if uniform else 'NO'}, "
          f"note vocabulary={len(NOTE_VOCAB)} entries, attacker-shaped notes dropped="
          f"{'yes' if not leaky and not echoed else 'NO'}")
    if recorded.get("note_dropped") is not True:
        failures.append("status hook accepted free text without marking it dropped")
    if not uniform or leaky or echoed:
        failures.append("display containment broken: the pet/hook could echo case text or resize the live frame")
    # Care clock (README §12): the one surface that speaks *unprompted*. Its cadence, the
    # moods it borrows and the parser's refusal to guess a mistyped spec are checked here,
    # because a reminder that silently re-enabled something disabled is a policy bug.
    from .ui.care import DEFAULT_REMINDERS, parse_reminders

    cadence = "/".join(f"{r.key}:{r.every_s / 60:.0f}" for r in DEFAULT_REMINDERS)
    moods_ok = all(r.mood in MOODS for r in DEFAULT_REMINDERS)
    parsed, unknown = parse_reminders("stretch=nonsense,bogus=5")
    refuses = not parsed and unknown == ["stretch=nonsense", "bogus=5"]
    print(f"care      : {len(DEFAULT_REMINDERS)} reminders at {cadence} min · moods all real="
          f"{'yes' if moods_ok else 'NO'} · bad spec refused without guessing={'yes' if refuses else 'NO'}")
    if not moods_ok or not refuses:
        failures.append("care clock: a reminder names a mood that does not exist, or a malformed spec was half-guessed")
    if failures:
        print("FAILURES  :", failures)
        return 1
    print("selftest  : ✅ all safety invariants hold")
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
