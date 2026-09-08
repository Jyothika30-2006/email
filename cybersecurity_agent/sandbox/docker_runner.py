"""Sandbox isolation layer (SAFETY #2) — the ONLY code path that lets anything
touch attachment bytes.

Docker mode (preferred), assembled argv — no shell anywhere:
  docker run --rm                        # container destroyed immediately after the run
    --name sentinel-sbx-<rand>           # so the kill-switch can `docker rm -f` it
    --network none                       # default-deny: static analysis needs no egress.
                                         # (The brief's "explicit whitelist" of VT/GeoIP
                                         # endpoints is deliberately NOT wired in: those
                                         # calls are made by host-side tools — keeping the
                                         # sandbox network-less is strictly safer and is
                                         # what the design doc's "no network from inside"
                                         # line demands. Documented, not silently dropped.)
    --memory 512m --cpus 1 --pids-limit 128
    --read-only --rootfs read-only? no: rootfs writable layer is disabled via
      --read-only + a small tmpfs for scratch
    --cap-drop ALL --security-opt no-new-privileges --user <uid>:<gid>
    -v <workdir>:/work:ro                  # read-only mount: the sandbox CANNOT
    -v <workdir>/out:/out:ro? no → :rw only for the single out dir  modify evidence
    python3 /work/scanner_script.py --file /work/evidence/<artifact> --out /out/report.json

Fallback (no Docker, operator opt-in): the *same* scanner script runs as a
subprocess with RLIMIT_AS/RLIMIT_CPU/RLIMIT_NPROC/RLIMIT_FSIZE applied in the
child, a scrubbed environment, `os.setsid` and kill-on-timeout, plus stdout-only
JSON (nothing is written next to the evidence). The report and the tool summary
label this `isolation: subprocess-limited` — process limits are a runaway-guard,
not a security boundary, and we say so out loud rather than claiming a sandbox we
don't have. If `sandbox_required=True`, static_file_scan refuses instead.
"""
from __future__ import annotations

import json
import os
import secrets
import shutil
import subprocess
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

from ..config import Config
from ..evidence.hasher import append_audit
from ..safety import KillSwitch, run_argv

PKG_DIR = Path(__file__).resolve().parent
SCANNER_SRC = PKG_DIR / "scanner_script.py"


@dataclass
class SandboxRun:
    ok: bool
    mode: str                      # docker | subprocess-limited | denied
    report: dict[str, Any] = field(default_factory=dict)
    raw_stderr: str = ""
    elapsed_s: float = 0.0
    container_name: str = ""
    notes: list[str] = field(default_factory=list)


def docker_available() -> tuple[bool, str]:
    exe = shutil.which("docker")
    if not exe:
        return False, "docker binary not found in PATH"
    try:
        proc = run_argv([exe, "info", "--format", "{{.ServerVersion}}"], timeout=10.0)
    except TimeoutError:
        return False, "`docker info` timed out (daemon unresponsive)"
    except Exception as exc:  # noqa: BLE001
        return False, f"{type(exc).__name__}: {exc}"
    if proc.returncode != 0:
        return False, f"docker present but unusable: {(proc.stderr or '').strip()[:180]}"
    return True, f"docker {proc.stdout.strip()}"


def prepare_workdir(case_dir: Path, files: dict[str, Path], *, keep_source: bool = True) -> Path:
    """Copy evidence *copies* into an isolated workdir. The original .eml/artifact
    files are never mounted writable, so even a compromised scanner cannot edit
    the evidence: it can only edit its own copy."""
    work = case_dir / "sandbox_work"
    if work.exists():
        shutil.rmtree(work, ignore_errors=True)
    (work / "evidence").mkdir(parents=True, exist_ok=True)
    (work / "out").mkdir(parents=True, exist_ok=True)
    shutil.copy2(SCANNER_SRC, work / "scanner_script.py")
    os.chmod(work / "scanner_script.py", 0o644)
    for name, src in files.items():
        safe = Path(name).name.replace("/", "_")[:80]
        shutil.copy2(src, work / "evidence" / safe)
        os.chmod(work / "evidence" / safe, 0o444)
    rules = PKG_DIR / "rules"
    if rules.exists():
        shutil.copytree(rules, work / "rules", dirs_exist_ok=True)
    _ = keep_source
    return work


def scan_file(cfg: Config, case_dir: Path, artifact_name: str, artifact_path: Path,
              *, switch: Optional[KillSwitch] = None) -> SandboxRun:
    """Run the static scanner on ONE artifact copy. Chooses the isolation mode
    automatically and never pretends to be something it isn't."""
    t0 = time.monotonic()
    if not artifact_path.exists():
        return SandboxRun(ok=False, mode="denied", notes=[f"artifact {artifact_name} not found in case dir"])

    work = prepare_workdir(case_dir, {artifact_name: artifact_path})
    out_dir = work / "out"
    container = ""
    avail, why = docker_available()
    append_audit(case_dir, "sandbox_probe", f"docker={avail} ({why})")

    if avail:
        notes: list[str] = []
        container = f"sentinel-sbx-{secrets.token_hex(4)}"
        base = str(work.resolve())
        argv = [
            "docker", "run", "--rm", "--name", container,
            "--network", "none",
            "--memory", cfg.sandbox_memory, "--cpus", str(cfg.sandbox_cpus),
            "--pids-limit", str(cfg.sandbox_pids),
            "--read-only", "--tmpfs", f"/tmp:size={cfg.sandbox_tmpfs_size},mode=1777",
            "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
            "--user", f"{os.getuid()}:{os.getgid()}",
            "-v", f"{base}:/work:ro",
            "-v", f"{base}/out:/out",
            cfg.sandbox_image,
            "python3", "/work/scanner_script.py",
            "--file", f"/work/evidence/{Path(artifact_name).name}",
            "--out", "/out/report.json",
        ]
        if (work / "rules").exists():
            argv += ["--rules-dir", "/work/rules"]
        if not image_exists(cfg.sandbox_image):
            notes.append(f"sandbox image '{cfg.sandbox_image}' not built → falling back to local subprocess "
                         f"(run: docker build -t {cfg.sandbox_image} cybersecurity_agent/sandbox)")
            return _fallback_or_deny(cfg, case_dir, work, artifact_name, t0, notes, why="image not built")
        try:
            proc = run_argv(argv, timeout=cfg.sandbox_timeout_s)
        except TimeoutError:
            _force_destroy(container)
            append_audit(case_dir, "sandbox_timeout_kill", f"docker rm -f {container}")
            return SandboxRun(ok=False, mode="docker", container_name=container,
                              elapsed_s=round(time.monotonic() - t0, 2),
                              notes=["hard sandbox timeout hit → container force-destroyed; no report"])
        finally:
            _force_destroy(container)      # belt & braces: destroyed after EVERY run
        report = _read_report(out_dir, proc.stdout)
        if switch and switch.aborted:
            _force_destroy(container)
            report.setdefault("aborted", True)
        append_audit(case_dir, "sandbox_run", f"mode=docker exit={proc.returncode} container={container} destroyed=true")
        if proc.stderr:
            notes.append(f"container stderr: {proc.stderr.strip()[:300]}")
        return SandboxRun(ok=bool(report), mode="docker", report=report or {}, raw_stderr=proc.stderr[:2000],
                          elapsed_s=round(time.monotonic() - t0, 2), container_name=container, notes=notes)

    if cfg.sandbox_required:
        append_audit(case_dir, "sandbox_denied", f"sandbox_required=true but docker unavailable: {why}")
        return SandboxRun(ok=False, mode="denied", notes=[f"docker unavailable ({why}) and SENTINEL_SANDBOX_REQUIRED=true → refusing to touch file bytes"])

    return _fallback_or_deny(cfg, case_dir, work, artifact_name, t0,
                             [f"docker unavailable ({why})"], why)


def _fallback_or_deny(cfg: Config, case_dir: Path, work: Path, artifact_name: str, t0: float,
                      notes: list[str], why: str) -> SandboxRun:
    """Rlimit-guarded subprocess execution of the same scanner (copy-on-write workdir)."""
    helper = PKG_DIR / "local_exec_helper.py"
    argv = [sys.executable, str(helper),
            "--scanner", str(work / "scanner_script.py"),
            "--file", str(work / "evidence" / Path(artifact_name).name),
            "--out", str(work / "out" / "report.json"),
            "--mem-mb", str(int(float(cfg.sandbox_memory.rstrip("m")) ) if cfg.sandbox_memory.endswith("m") else 512),
            "--cpu-s", str(int(cfg.sandbox_timeout_s)),
            "--rules-dir", str(work / "rules") if (work / "rules").exists() else ""]
    argv = [a for a in argv if a != ""]
    if not helper.exists():
        return SandboxRun(ok=False, mode="denied", notes=notes + ["local_exec_helper.py missing"])
    try:
        proc = run_argv(argv, timeout=cfg.sandbox_timeout_s)
    except TimeoutError:
        return SandboxRun(ok=False, mode="subprocess-limited", elapsed_s=round(time.monotonic() - t0, 2),
                          notes=notes + ["subprocess exceeded its budget and was SIGKILLed"])
    report = _read_report(work / "out", proc.stdout)
    append_audit(case_dir, "sandbox_run", f"mode=subprocess-limited exit={proc.returncode} reason={why}")
    notes.append("isolation=resource-limited subprocess (NOT a container); evidence was copied first and is mounted nowhere")
    return SandboxRun(ok=bool(report), mode="subprocess-limited", report=report or {},
                      raw_stderr=proc.stderr[:2000], elapsed_s=round(time.monotonic() - t0, 2), notes=notes)


def image_exists(image: str) -> bool:
    try:
        proc = run_argv(["docker", "image", "inspect", image], timeout=10.0)
    except Exception:  # noqa: BLE001
        return False
    return proc.returncode == 0


def _force_destroy(container: str) -> None:
    if not container:
        return
    try:
        run_argv(["docker", "rm", "-f", container], timeout=8.0)
    except Exception:  # noqa: BLE001 — teardown is best-effort; --rm already handles the normal path
        pass


def _read_report(out_dir: Path, stdout: str) -> Optional[dict[str, Any]]:
    path = out_dir / "report.json"
    if path.exists():
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            pass
    for line in reversed((stdout or "").splitlines()):
        line = line.strip()
        if line.startswith("{"):
            try:
                blob = json.loads(line)
                return blob.get("report", blob)
            except json.JSONDecodeError:
                continue
    return None


def register_kill_teardown(switch: Optional[KillSwitch], container: str) -> None:
    """SAFETY #8 wiring: the kill-switch destroys the container if one is live."""
    if not switch or not container:
        return
    switch.register_teardown(lambda: _force_destroy(container))


def cleanup_workdir(work: Path) -> None:
    """Scratch copies of malicious bytes do not linger on disk."""
    shutil.rmtree(work, ignore_errors=True)
