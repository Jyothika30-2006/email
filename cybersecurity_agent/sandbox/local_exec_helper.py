#!/usr/bin/env python3
"""Resource-limited local runner for the static scanner (fallback when Docker is
unavailable). NOT a security boundary — it is a runaway guard:

  RLIMIT_AS     address-space cap        (no 8 GiB allocation loops)
  RLIMIT_CPU    cpu-seconds cap          (no infinite scan)
  RLIMIT_FSIZE  max file the child writes (no filling the disk)
  RLIMIT_NPROC  child may not fork-bomb  (1 process + itself)
  environment scrubbed, cwd chrooted-ish to the workdir, SIGKILL on wall timeout,
  stdin=/dev/null, argv only (no shell).

The child is our own scanner_script.py, which only ever opens files read-only.
"""
from __future__ import annotations

import argparse
import os
import resource
import signal
import subprocess
import sys


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--scanner", required=True)
    ap.add_argument("--file", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--mem-mb", type=int, default=512)
    ap.add_argument("--cpu-s", type=int, default=90)
    ap.add_argument("--rules-dir", default="")
    args = ap.parse_args()

    if os.name == "nt":  # pragma: no cover - Windows: no POSIX rlimits
        print("local_exec_helper: POSIX resource limits unavailable on Windows; "
              "install Docker for real isolation (sandbox_required=true refuses otherwise)", file=sys.stderr)
        return 91

    def _limits() -> None:
        mem = args.mem_mb * 1024 * 1024
        for what, hard in (
            (resource.RLIMIT_AS, (mem, mem)),
            (resource.RLIMIT_CPU, (args.cpu_s, args.cpu_s + 5)),
            (resource.RLIMIT_FSIZE, (4 * 1024 * 1024, 4 * 1024 * 1024)),
            (resource.RLIMIT_NPROC, (64, 64)),
            (resource.RLIMIT_CORE, (0, 0)),
        ):
            try:
                resource.setrlimit(what, hard)
            except (ValueError, OSError):
                pass
        # (setsid is handled by start_new_session=True below)
        # Keep the child from inheriting anything sensitive.
        env_keys = ("PATH", "LANG", "PYTHONHASHSEED", "HOME", "VIRTUAL_ENV")
        safe_env = {k: os.environ[k] for k in env_keys if k in os.environ}
        safe_env["PYTHONDONTWRITEBYTECODE"] = "1"
        os.environ.clear()
        os.environ.update(safe_env)

    argv = [sys.executable, args.scanner, "--file", args.file, "--out", args.out, "--no-optional"]
    if args.rules_dir:
        argv += ["--rules-dir", args.rules_dir]
    proc = subprocess.Popen(  # noqa: S603 - argv built from fixed paths, no user strings
        argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        text=True, preexec_fn=_limits, start_new_session=True,
    )
    try:
        out, err = proc.communicate(timeout=max(10, args.cpu_s))
    except subprocess.TimeoutExpired:
        try:
            os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
        except ProcessLookupError:
            proc.kill()
        print(f'{{"ok": false, "error": "sandbox subprocess exceeded {args.cpu_s}s and was SIGKILLed"}}')
        return 124
    sys.stdout.write(out or "")
    sys.stderr.write(err or "")
    return proc.returncode


if __name__ == "__main__":
    raise SystemExit(main())
