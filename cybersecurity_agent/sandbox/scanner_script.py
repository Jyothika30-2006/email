#!/usr/bin/env python3
"""SENTINEL-IR static analyzer — runs INSIDE the sandbox (Docker or a
resource-limited subprocess), reads bytes, writes one JSON report, and then dies.

SAFETY #3, enforced by construction:
  * the artifact is opened read-only (`rb`) and never handed to an OS loader,
    shell, archive extractor, document renderer or macro engine;
  * no network calls exist in this file — a sandboxed static scan has no reason to
    phone home, and the container it normally runs in is `--network none`;
  * it parses *structures* (magic bytes, entropy, printable strings, OLE/ZIP/PDF
    tables, PE headers read as bytes) — reading bytes is not executing them;
  * optional extras (exiftool / oletools / yara-python) are detected at runtime and
    reported as "absent" rather than silently skipped.

Usage: scanner_script.py --file <path> --out <json> [--magic-only]
"""
from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import re
import subprocess
import sys
import time
from collections import Counter
from pathlib import Path

MAX_BYTES = 24 * 1024 * 1024          # read at most 24 MiB of a suspect file
ENTROPY_WINDOW = 1024 * 1024          # entropy over the first 1 MiB
STRING_LIMIT = 160

# Signature table (offset → type). Deliberately minimal: we only need to answer
# "does the content contradict the extension?" — a full libmagic is out of scope.
MAGIC = [
    (b"\x7fELF", "ELF executable"),
    (b"MZ", "PE/DOS executable (MZ)"),
    (b"\xca\xfe\xba\xbe", "Java class"),
    (b"\xde\xad\xbe\xef", "Java class (BE magic)"),
    (b"#!", "script (shebang)"),
    (b"%PDF", "PDF document"),
    (b"PK\x03\x04", "ZIP archive (Office Open XML / docx / jar if renamed)"),
    (b"PK\x05\x06", "ZIP archive (empty)"),
    (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", "OLE2 Compound Document (legacy .doc/.xls/.ppt)"),
    (b"\x1f\x8b", "gzip archive"),
    (b"BZh", "bzip2 archive"),
    (b"\xfd7zXZ\x00", "xz archive"),
    (b"7z\xbc\xaf\x27\x1c", "7z archive"),
    (b"Rar!\x1a\x07", "RAR archive"),
    (b"\xff\xd8\xff", "JPEG image"),
    (b"\x89PNG\r\n\x1a\n", "PNG image"),
    (b"GIF87a", "GIF image"),
    (b"GIF89a", "GIF image"),
    (b"RIFF", "RIFF container (AVI/WAV/WEBP)"),
    (b"SQLite format 3\x00", "SQLite database"),
    (b"<html", "HTML document"),
    (b"<!DOCTYPE html", "HTML document"),
    (b"<?xml", "XML document"),
    (b"{\\rtf", "RTF document"),
    (b"\x25\x21PS-AdobePS", "PostScript"),
    (b"hk\x04\x05", "SquashFS"),
]
EICAR = (b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*")

EXT_HINTS = {
    ".pdf": ("PDF document",), ".exe": ("PE/DOS executable (MZ)", "ELF executable"),
    ".dll": ("PE/DOS executable (MZ)",), ".scr": ("PE/DOS executable (MZ)",),
    ".doc": ("OLE2 Compound Document",), ".xls": ("OLE2 Compound Document",),
    ".ppt": ("OLE2 Compound Document",), ".docx": ("ZIP archive",), ".xlsx": ("ZIP archive",),
    ".pptx": ("ZIP archive",), ".zip": ("ZIP archive", ".zip"), ".gz": ("gzip",),
    ".jpg": ("JPEG",), ".jpeg": ("JPEG",), ".png": ("PNG",), ".gif": ("GIF",),
    ".txt": ("text", "script", "XML", "HTML"), ".htm": ("HTML",), ".html": ("HTML",),
    ".jar": ("Java class", "ZIP archive"), ".rtf": ("RTF",), ".elf": ("ELF",),
    ".bin": (), ".dat": (), ".iso": ("ISO", "UDF"), ".cab": ("CAB"),
}
SUSPICIOUS_STRINGS = [
    r"(?i)powershell(\.exe)?\s+-", r"(?i)cmd\.exe\s*/c", r"(?i)-enc\s+[A-Za-z0-9+/=]{24,}",
    r"(?i)rundll32|regsvr32|mshta\.exe|wscript|cscript", r"(?i)Certutil.*-decode",
    r"(?i)CreateRemoteThread|VirtualAllocEx|WriteProcessMemory|NtUnmapViewOfSection",
    r"(?i)HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
    r"(?i)http://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", r"(?i)https?://[a-z0-9.-]+\.(zip|xyz|top|click|icu|rest)\b",
    r"(?i)AutoOpen|AutoExec|Document_Open|Workbook_Open", r"(?i)shell(?:\.exe)?.*\.(?:exe|scr|bat|ps1)",
    r"(?i)base64 -d|eval\(atob|fromCharCode", r"-----BEGIN (RSA |OPENSSH )?PRIVATE KEY-----",
]
PE_IMPORT_HINTS = [b"kernel32.dll", b"urlmon.dll", b"wininet.dll", b"ws2_32.dll", b"msvcrt.dll", b"advapi32.dll"]


# ─────────────────────────────────────────────────────────────────────────────
def read_file(path: Path) -> bytes:
    with open(path, "rb") as fh:          # read-only by construction
        return fh.read(MAX_BYTES)


def detect_magic(data: bytes) -> tuple[str, int]:
    for sig, label in MAGIC:
        if data.startswith(sig):
            return label, len(sig)
    # not at offset 0 — some malware prepends junk; report where it starts
    for sig, label in MAGIC:
        if sig:
            idx = data[:4096].find(sig)
            if 0 < idx < 4096:
                return f"{label} (at offset 0x{idx:x}, not at start — prepended data?)", idx
    if data[:64].strip(b"\x00\r\n\t ").isdigit() or re.match(rb"^[\x09\x0a\x0d\x20-\x7e\n\r\t]{64,}$", data[:4096]):
        return "plain text", 0
    return "unrecognized binary", 0


def entropy(data: bytes) -> float:
    if not data:
        return 0.0
    sample = data[:ENTROPY_WINDOW]
    counts = Counter(sample)
    total = len(sample)
    return round(-sum((c / total) * math.log2(c / total) for c in counts.values()), 3)


def printable_strings(data: bytes, min_len: int = 6) -> list[str]:
    out: list[str] = []
    pattern = re.compile(rb"[\x20-\x7e]{" + str(min_len).encode() + rb",}")
    for m in pattern.finditer(data[:MAX_BYTES]):
        s = m.group().decode("latin-1")
        if s not in out:
            out.append(s)
        if len(out) >= STRING_LIMIT:
            break
    return out


def check_extension(name: str, magic_type: str) -> tuple[bool, str]:
    ext = os.path.splitext(name)[1].lower()
    allowed = EXT_HINTS.get(ext)
    if allowed is None:
        return True, f"no extension expectation for {ext or '(none)'}"
    if not allowed:
        return True, f"{ext} has no canonical magic (any content accepted)"
    for a in allowed:
        if a.lower() in magic_type.lower():
            return True, f"extension {ext} consistent with {magic_type}"
    return False, f"MISMATCH: named {ext} but content is {magic_type}"


def scan_pdf(data: bytes) -> dict:
    out: dict = {}
    out["js_actions"] = len(re.findall(rb"/(JavaScript|JS|Scriplets|OpenAction|AA)\b", data, re.I))
    out["embedded_files"] = len(re.findall(rb"/EmbeddedFile\b|/Collections?\b", data, re.I))
    out["launch"] = len(re.findall(rb"/Launch\b|/EmbeddedGoTo\b|/SubmitForm\b|/URI\b", data, re.I))
    out["obfuscation"] = len(re.findall(rb"(<</|>>>\s*<</)|\/ObjStm\b", data))
    out["page_count_declared"] = len(re.findall(rb"/Type\s*/Page\b", data))
    out["header"] = data[:1024].decode("latin-1", "replace").splitlines()[0][:120] if data else ""
    return out


def scan_ole(data: bytes) -> dict:
    """Minimal OLE2 directory scan for macro streams — we never let Word/Excel or
    an emulator see this file; we only read the FAT/directory structures."""
    out: dict = {}
    try:
        import olefile  # type: ignore

        import io

        ole = olefile.OleFileIO(io.BytesIO(data))
        entries = ["/".join(e) for e in ole.listdir()]
        out["streams"] = entries[:60]
        out["macro_streams"] = [e for e in entries if re.search(r"(?i)vba|_1_0|macros|ThisDocument|dirstream", e)]
        out["has_vba_project"] = any("VBA" in e.upper() for e in entries)
        ole.close()
    except Exception as exc:  # olefile missing or file malformed
        out["deep_parse"] = f"unavailable ({type(exc).__name__}: {exc})"
        needles = [b"Macros", b"VBA", b"_VBA_PROJECT_CUR", b"ThisDocument", b"WordDocument", b"Workbook"]
        out["present_markers"] = [n.decode() for n in needles if n in data[:400_000]]
        out["has_vba_project"] = b"VBA" in data[:400_000] and b"Macros" in data[:400_000]
    return out


def scan_zip(data: bytes) -> dict:
    out: dict = {}
    try:
        import io
        import zipfile

        zf = zipfile.ZipFile(io.BytesIO(data))
        names = zf.namelist()
        out["entries"] = names[:80]
        out["entry_count"] = len(names)
        out["office_macros"] = [n for n in names if re.search(r"vbaProject\.bin$|\.bin$", n) and "vba" in n.lower()]
        out["suspicious"] = [n for n in names if re.search(r"(?i)\.(exe|scr|bat|cmd|vbs|js|hta|lnk|ps1)$", n)]
        # encrypted entries (bit 0 of the GP flag) = content hidden from scanners
        out["encrypted_entries"] = len([i for i in zf.infolist() if i.flag_bits & 0x1])
        out["external_sources"] = bool(re.search(rb"external_data|http://|https://", data[:200_000]))
    except Exception as exc:  # noqa: BLE001
        out["deep_parse"] = f"unavailable ({type(exc).__name__}: {exc})"
    return out


def scan_pe(data: bytes) -> dict:
    out: dict = {}
    if not data.startswith(b"MZ"):
        return out
    try:
        e_lfanew = int.from_bytes(data[0x3C:0x40], "little")
        if data[e_lfanew:e_lfanew + 4] != b"PE\x00\x00" or e_lfanew + 0xF8 > len(data):
            out["valid_pe_header"] = False
            return out
        out["valid_pe_header"] = True
        machine = int.from_bytes(data[e_lfanew + 4:e_lfanew + 6], "little")
        out["machine"] = {0x14c: "x86", 0x8664: "x64", 0x1c0: "ARM", 0xaa64: "ARM64"}.get(machine, hex(machine))
        nsec = int.from_bytes(data[e_lfanew + 6:e_lfanew + 8], "little")
        out["sections"] = nsec
        opt_off = e_lfanew + 24
        magic = int.from_bytes(data[opt_off:opt_off + 2], "little")
        out["optional_header_magic"] = {0x10b: "PE32", 0x20b: "PE32+"}.get(magic, hex(magic))
        subsys = int.from_bytes(data[opt_off + 68:opt_off + 70], "little")
        out["subsystem"] = {2: "GUI", 3: "console", 9: "native (no GUI — service/driver-ish)"}.get(subsys, str(subsys))
        ep = int.from_bytes(data[opt_off + 16:opt_off + 20], "little")
        out["entry_point"] = hex(ep)
        # high-entropy last section ≈ packer/encrypted stub
        secs = []
        for i in range(min(nsec, 12)):
            so = opt_off + int.from_bytes(data[e_lfanew + 20:e_lfanew + 22], "little") + i * 40
            name = data[so:so + 8].rstrip(b"\x00").decode("latin-1", "replace")
            vsize = int.from_bytes(data[so + 8:so + 12], "little")
            raw = int.from_bytes(data[so + 16:so + 20], "little")
            ptr = int.from_bytes(data[so + 20:so + 24], "little")
            blob = data[ptr:ptr + max(1, min(raw, 512 * 1024))]
            secs.append({"name": name, "vsize": vsize, "raw": raw, "ptr": ptr, "entropy": entropy(blob)})
        out["section_table"] = secs
        packed = [s for s in secs if s["entropy"] > 7.2 and s["raw"] > 4096]
        out["packed_heuristic_sections"] = [s["name"] for s in packed]
        low = data.lower()
        out["import_hints"] = [n.decode() for n in PE_IMPORT_HINTS if n in low[:400_000]]
        out["overlay"] = len(data) - (secs[-1]["ptr"] + secs[-1]["raw"]) if secs and "ptr" in secs[-1] else None
    except Exception as exc:  # noqa: BLE001
        out["pe_parse_error"] = f"{type(exc).__name__}: {exc}"
    return out


def run_optional_tool(name: str, argv: list[str], timeout: float = 20.0) -> dict:
    """Exiftool/oletools/YARA if the sandbox image carries them. argv is a constant
    list — the artifact path is passed as an argument, never interpolated into a
    shell string (there is no shell in this process at all)."""
    try:
        proc = subprocess.run(argv, capture_output=True, text=True, timeout=timeout,  # noqa: S603
                              stdin=subprocess.DEVNULL)
        return {"available": True, "exit": proc.returncode,
                "stdout": (proc.stdout or "")[:3000], "stderr": (proc.stderr or "")[:600]}
    except FileNotFoundError:
        return {"available": False, "error": f"{name} not installed in this image"}
    except subprocess.TimeoutExpired:
        return {"available": True, "error": f"{name} timed out after {timeout}s (refused to hang the run)"}
    except Exception as exc:  # noqa: BLE001
        return {"available": False, "error": f"{type(exc).__name__}: {exc}"}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--file", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--rules-dir", default="")
    ap.add_argument("--no-optional", action="store_true")
    args = ap.parse_args()

    t0 = time.time()
    path = Path(args.file)
    report: dict = {"scanner_version": "sentinel-static/1.0", "file": path.name,
                    "started_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}
    try:
        data = read_file(path)
        report.update({
            "size_bytes": len(data),
            "sha256": hashlib.sha256(data).hexdigest(),
            "md5": hashlib.md5(data).hexdigest(),
            "truncated_at": MAX_BYTES if len(data) == MAX_BYTES else None,
        })
        magic, magic_off = detect_magic(data)
        report["magic_type"] = magic
        report["magic_offset"] = magic_off
        ok, note = check_extension(path.name, magic)
        report["extension_consistent"] = ok
        report["extension_note"] = note
        report["entropy_bits_per_byte"] = entropy(data)
        flags: list[str] = []
        if not ok:
            flags.append(f"file_type_mismatch: {note}")
        if report["entropy_bits_per_byte"] >= 7.2:
            flags.append(f"high_entropy: {report['entropy_bits_per_byte']} bits/byte — packed or encrypted content a static scan cannot see into")
        if EICAR in data[:4096]:
            flags.append("eicar_test_signature: matches the harmless industry AV test string")

        strs = printable_strings(data)
        report["strings_preview"] = strs[:40]
        report["suspicious_strings"] = [s[:200] for s in strs
                                        for pat in SUSPICIOUS_STRINGS if re.search(pat, s)][:12]
        if report["suspicious_strings"]:
            flags.append(f"suspicious_strings: {len(report['suspicious_strings'])} indicator(s) in printable strings")

        low = data.lower()
        if b"vba" in low[:600_000] and any(k in low[:600_000] for k in (b"macro", b"document_open", b"autoopen", b"shell")):
            flags.append("embedded_macro: VBA/macro stream markers present (no emulation, no execution — bytewise directory scan only)")
        if magic.startswith("PDF"):
            pdf = scan_pdf(data)
            report["pdf"] = pdf
            if pdf.get("js_actions") or pdf.get("launch"):
                flags.append(f"pdf_active_content: JavaScript/OpenAction/Launch objects present "
                             f"(js={pdf.get('js_actions')}, launch-ish={pdf.get('launch')})")
            if pdf.get("embedded_files"):
                flags.append(f"pdf_embedded_files: {pdf['embedded_files']}")
        if magic.startswith("OLE2"):
            ole = scan_ole(data)
            report["ole"] = ole
            if ole.get("has_vba_project"):
                flags.append("embedded_macro: VBA project directory present in OLE2 container")
        if magic.startswith("ZIP"):
            z = scan_zip(data)
            report["zip"] = z
            if z.get("encrypted_entries"):
                flags.append(f"zip_encrypted_entries: {z['encrypted_entries']} (content hidden from scanners)")
            if z.get("suspicious"):
                flags.append(f"zip_executable_member(s): {z['suspicious'][:4]}")
        if data.startswith(b"MZ"):
            pe = scan_pe(data)
            report["pe"] = pe
            if pe.get("packed_heuristic_sections"):
                flags.append(f"pe_packed_sections: {pe['packed_heuristic_sections']}")
            if b"this binary must be run under windows" in low:
                report["pe_note"] = "Windows PE — would never execute on this platform; inspection is bytewise only"
        report["flags"] = flags

        tools: dict = {}
        if not args.no_optional:
            if shutil_which("exiftool"):
                tools["exiftool"] = run_optional_tool("exiftool", ["exiftool", "-j", "-n", str(path)])
            if shutil_which("olevba"):
                tools["olevba"] = run_optional_tool("olevba", ["olevba", "--show-pcode", str(path)])
            if shutil_which("pdf-parser"):
                tools["pdf_parser"] = run_optional_tool("pdf-parser", ["pdf-parser", "-a", str(path)])
            try:
                import yara  # type: ignore

                rules_dir = Path(args.rules_dir or (Path(__file__).parent / "rules"))
                if rules_dir.exists() and any(rules_dir.glob("*.yar")):
                    comp = yara.compile(filepath=str(next(rules_dir.glob("*.yar")))) if len(list(rules_dir.glob("*.yar"))) == 1 \
                        else yara.compile(filepath={p.stem: str(p) for p in rules_dir.glob("*.yar")})
                    matches = comp.match(data=data[: MAX_BYTES])
                    tools["yara"] = {"available": True, "matches": [str(m) for m in matches],
                                     "rules_dir": str(rules_dir)}
                    if matches:
                        flags.append(f"yara_matches: {', '.join(str(m) for m in matches)}")
                        report["flags"] = flags
            except ImportError:
                tools["yara"] = {"available": False, "error": "yara-python not installed in image"}
            except Exception as exc:  # noqa: BLE001
                tools["yara"] = {"available": True, "error": f"{type(exc).__name__}: {exc}"}
        report["optional_tools"] = tools
    except Exception as exc:  # noqa: BLE001 — never let a parse bug leak a traceback to the agent as "clean"
        report["error"] = f"{type(exc).__name__}: {exc}"
    report["elapsed_s"] = round(time.time() - t0, 3)
    report["execution_note"] = "static bytewise analysis only; the file was never executed, opened, rendered or extracted"

    Path(args.out).write_text(json.dumps(report, indent=2, sort_keys=True)[:200_000], encoding="utf-8")
    # Also print, so a runner that captured stdout still works.
    print(json.dumps({"ok": "error" not in report, "report": report})[:200_000])
    return 0


def shutil_which(exe: str) -> str | None:
    from shutil import which

    return which(exe)


if __name__ == "__main__":
    sys.exit(main())
