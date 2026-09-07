"""`.eml` parsing: envelope fields, Received-hop walking, auth headers,
Message-ID forensics, Date-offset hints, body/attachment extraction, and the
brand/homoglyph knowledge base used by extract_urls.

Header walking convention: RFC 5321 prepends each `Received:` block, so the
*bottom-most* Received header is the oldest hop (closest to the sender). We
number hops bottom→top (`sequence` 0 = oldest) and always iterate ascending,
which makes "walk from bottom, skipping provider relay hops" a plain loop.
"""
from __future__ import annotations

import base64
import email
import io
import email.policy
import quopri
import re
from dataclasses import dataclass, field
from email.parser import BytesParser
from email.headerregistry import Address
from typing import Any, Optional

from ..models import Hop

# ─────────────────────────────────────────────────────────────────────────────
# Provider relay infrastructure (the thing that hides the sender IP)
# ─────────────────────────────────────────────────────────────────────────────
RELAY_DOMAINS: dict[str, str] = {
    "google.com": "Google", "gmail.com": "Google", "googlemail.com": "Google",
    "googleusercontent.com": "Google", "gstatic.com": "Google",
    "outlook.com": "Microsoft", "hotmail.com": "Microsoft", "microsoft.com": "Microsoft",
    "microsoftonline.com": "Microsoft", "office365.com": "Microsoft", "outlook.office365.com": "Microsoft",
    "live.com": "Microsoft", "messageengine.net": "Microsoft", "protection.outlook.com": "Microsoft",
    "yahoo.com": "Yahoo", "yahoodns.net": "Yahoo",
    "icloud.com": "Apple", "me.com": "Apple", "apple.com": "Apple",
    "protonmail.com": "Proton", "proton.me": "Proton", "pm.me": "Proton",
}

IP_IN_BRACKETS = re.compile(r"\[(\d{1,3}(?:\.\d{1,3}){3})\]")
IP_BARE = re.compile(r"(?<![\d.])(\d{1,3}(?:\.\d{1,3}){3})(?![\d.])")
HOST_RE = re.compile(r"\b([A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)(?:\.([A-Za-z0-9-]{1,61})+)*\b")
URL_RE = re.compile(r"""(?:href|src)\s*=\s*["']?(https?://[^\s"'<>)]+)["']?|(?<![A-Za-z0-9_.:/-])(https?://[^\s"'<>)\]]+)""", re.IGNORECASE)
MSGID_HOST_RE = re.compile(r"@([^\s>\]\)]+)$")
OFFSET_RE = re.compile(r"([+-])(\d{2})(\d{2})\s*$")

TZ_OFFSET_HINTS: dict[str, tuple[str, str]] = {
    "+0530": ("India (IST)", "low"), "+0550": ("Kolkata-district legacy zone", "low"),
    "+0300": ("Eastern Europe / Moscow / Nairobi", "low"), "+0200": ("Central/Western Europe, Nigeria", "low"),
    "+0100": ("Western Europe", "low"), "+0800": ("China/Singapore/W.Australia", "low"),
    "+0900": ("Japan/Korea", "low"), "-0500": ("US East / Colombia / Peru", "low"),
    "-0400": ("US East (EDT) / Venezuela", "low"), "-0800": ("US West (PST)", "low"),
    "+0400": ("UAE", "low"), "+0330": ("Iran", "low"), "+0600": ("Bangladesh", "low"),
    "+0700": ("Thailand/Vietnam/Indonesia", "low"), "-0600": ("Central America", "low"),
}

BRANDS: dict[str, dict[str, Any]] = {
    "paypal": {"domains": {"paypal.com"}, "phrases": ["paypal"]},
    "google": {"domains": {"google.com", "accounts.google.com"}, "phrases": ["google"]},
    "microsoft": {"domains": {"microsoft.com", "login.live.com", "office.com", "office365.com"}, "phrases": ["microsoft", "office 365"]},
    "apple": {"domains": {"apple.com", "id.apple.com"}, "phrases": ["apple id", "icloud"]},
    "netflix": {"domains": {"netflix.com"}, "phrases": ["netflix"]},
    "amazon": {"domains": {"amazon.com", "amzn.to"}, "phrases": ["amazon", "prime"]},
    "dhl": {"domains": {"dhl.com", "dhl.us"}, "phrases": ["dhl"]},
    "chase": {"domains": {"chase.com"}, "phrases": ["chase bank"]},
    "sbi": {"domains": {"sbi.co.in"}, "phrases": ["state bank of india", "sbi"]},
    "hdfc": {"domains": {"hdfcbank.com"}, "phrases": ["hdfc"]},
    "github": {"domains": {"github.com"}, "phrases": ["github"]},
    "linkedin": {"domains": {"linkedin.com"}, "phrases": ["linkedin"]},
    "dropbox": {"domains": {"dropbox.com"}, "phrases": ["dropbox"]},
    "zoom": {"domains": {"zoom.us"}, "phrases": ["zoom"]},
    "gmail": {"domains": {"gmail.com", "accounts.google.com"}, "phrases": ["gmail"]},
    "okta": {"domains": {"okta.com"}, "phrases": ["okta"]},
}

SHORTENERS = {
    "bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly", "is.gd", "buff.ly",
    "rb.gy", "cutt.ly", "rebrand.ly", "shorturl.at", "tiny.cc", "urlz.fr", "v.gd",
}

# Characters commonly swapped in typosquatted domains (Cyrillic/Greek → Latin look).
HOMOGLYPHS = {
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "у": "y", "х": "x",
    "і": "i", "ј": "j", "ѕ": "s", "ԁ": "d", "ӏ": "l", "ԛ": "q", "ԝ": "w",
    "ɡ": "g", "һ": "h", "к": "k", "Μ": "M", "ν": "v",
}
LOOKALIKE_DIGITS = {"0": "o", "1": "l", "3": "e", "5": "s", "7": "t", "8": "b", "9": "g"}
SUSPICIOUS_TLDS = {
    "zip", "xyz", "top", "cam", "click", "link", "work", "gq", "ml", "cf", "tk",
    "ga", "biz", "rest", "buzz", "icu", "quest", "shop", "live", "review",
}
RISKY_EXTENSIONS = {".exe", ".dll", ".scr", ".pif", ".jar", ".vbs", ".vbe", ".js", ".jse",
                    ".lnk", ".hta", ".msi", ".bat", ".cmd", ".ps1", ".com", ".chm", ".iso",
                    ".img", ".docm", ".xlsm", ".pptm", ".dotm", ".xla", ".html", ".htm", ".url", ".application"}

# High-signal phrases (urgency + credential harvesting), tuned for phishing, not
# for content moderation. Absence of these never lowers risk.
URGENCY_PATTERNS = [
    r"\b(urgent|immediately|within\s+(24|48|\d+)\s*hours?|last\s+warning|account\s+(will\s+be\s+)?(suspend|deactivat|clos))\w*",
    r"\b(action\s+required|verify\s+your|re-?validate|unusual\s+(sign-?in|activity)|payment\s+(has\s+)?failed)\b",
]
CRED_HARVEST_PATTERNS = [
    r"\b(verify|confirm|validate|re-?enter|update)\b[^.\n]{0,40}\b(password|credentials?|sign-?in|login|card\s+number|otp)\b",
    r"action_required|/signin\?|/login\?|redirect_uri=|webscr|update_info\.php|session=expire",
]


@dataclass
class ParsedEmail:
    """Everything static parsing can give us, before any network call."""
    path: str = ""
    size_bytes: int = 0
    headers: dict[str, list[str]] = field(default_factory=dict)
    envelope: dict[str, str] = field(default_factory=dict)
    received_raw: list[str] = field(default_factory=list)
    hops: list[Hop] = field(default_factory=list)
    auth_results: list[dict[str, Any]] = field(default_factory=list)
    received_spf: list[dict[str, Any]] = field(default_factory=list)
    message_id: str = ""
    message_id_host: str = ""
    date_raw: str = ""
    tz_offset: str = ""
    tz_minutes: int = 0
    text_body: str = ""
    html_body: str = ""
    attachments: list[dict[str, Any]] = field(default_factory=list)
    dkim: dict[str, Any] = field(default_factory=dict)
    notes: list[str] = field(default_factory=list)

    def header(self, name: str, default: str = "") -> str:
        vals = self.headers.get(name.lower())
        return vals[0] if vals else default

    def as_digest(self) -> dict[str, Any]:
        """Compact, network-free view — what the LLM is shown first."""
        return {
            "from": self.envelope.get("from", ""),
            "reply_to": self.envelope.get("reply-to", ""),
            "return_path": self.envelope.get("return-path", ""),
            "to": self.envelope.get("to", ""),
            "subject": self.envelope.get("subject", ""),
            "date": self.date_raw,
            "tz_offset": self.tz_offset,
            "message_id": self.message_id,
            "message_id_host": self.message_id_host,
            "x_mailer": self.envelope.get("x-mailer", ""),
            "hop_count": len(self.hops),
            "hops": [h.as_dict() for h in self.hops],
            "auth_results": self.auth_results,
            "received_spf": self.received_spf,
            "dkim_record": self.dkim,
            "attachment_count": len(self.attachments),
            "attachments": [{k: v for k, v in a.items() if k != "payload"} for a in self.attachments],
            "notes": self.notes,
        }


# ─────────────────────────────────────────────────────────────────────────────
# Entry point
# ─────────────────────────────────────────────────────────────────────────────
def parse_eml(path: str | Any) -> ParsedEmail:
    with open(path, "rb") as fh:
        raw = fh.read()
    return parse_bytes(raw, path=str(path))


def parse_bytes(raw: bytes, *, path: str = "") -> ParsedEmail:
    # BytesParser (not message_from_binary_file) so we can hand it an in-memory
    # stream — the file on disk is never rewritten, only read (SAFETY #6).
    msg = BytesParser(policy=email.policy.SMTPUTF8).parse(io.BytesIO(raw))
    parsed = ParsedEmail(path=path, size_bytes=len(raw))

    for key, value in msg.items():
        parsed.headers.setdefault(key.lower(), []).append(str(value))

    parsed.received_raw = list(msg.get_all("Received", []))
    parsed.hops = parse_received_hops(parsed.received_raw)
    parsed.auth_results = parse_auth_results(parsed.headers.get("authentication-results", []))
    parsed.received_spf = parse_received_spf(parsed.headers.get("received-spf", []))
    parsed.message_id = str(msg.get("Message-ID", "") or "").strip("<> ")
    m = MSGID_HOST_RE.search(parsed.message_id)
    parsed.message_id_host = _clean_host(m.group(1)) if m else ""
    parsed.date_raw = str(msg.get("Date", "") or "").strip()
    off = _tz_offset_minutes(parsed.date_raw)
    parsed.tz_offset = f"{off:+d} minutes" if off else "none"
    parsed.tz_minutes = off
    parsed.dkim = parse_dkim_signature(parsed.headers.get("dkim-signature", [""])[0])
    parsed.envelope = _envelope(msg)
    parsed.text_body, parsed.html_body, parsed.attachments = extract_bodies(msg)
    parsed.notes = structural_notes(parsed)
    return parsed


# ─────────────────────────────────────────────────────────────────────────────
# Envelope + header helpers
# ─────────────────────────────────────────────────────────────────────────────
def _display_and_addr(raw: str) -> tuple[str, str]:
    if not raw:
        return "", ""
    m = re.match(r"\s*(?P<disp>\"?[^\"]*\"?)\s*<(?P<addr>[^>]+)>", raw)
    if m:
        return m.group("disp").strip().strip('"'), m.group("addr").strip()
    return "", raw.strip()


def _envelope(msg: Any) -> dict[str, str]:
    out: dict[str, str] = {}
    for name in ("from", "to", "cc", "subject", "reply-to", "return-path", "sender",
                  "x-mailer", "user-agent", "organization", "message-id"):
        vals = msg.get_all(name)
        if vals:
            out[name] = ", ".join(str(v).strip() for v in vals)
    return out


def addr_of(raw: str) -> str:
    return _display_and_addr(raw)[1]


def domain_of(addr: str) -> str:
    return addr.rsplit("@", 1)[-1].strip(">").lower() if "@" in addr else ""


def display_name_of(raw: str) -> str:
    return _display_and_addr(raw)[0]


def _clean_host(value: str) -> str:
    host = re.sub(r"[^A-Za-z0-9.\-:_\[\]]", "", value or "").strip(".").lower()
    return host


# ─────────────────────────────────────────────────────────────────────────────
# Received: hop walking  (tool: parse_headers)
# ─────────────────────────────────────────────────────────────────────────────
def parse_received_hops(received_lines: list[str]) -> list[Hop]:
    """Bottom→top numbering. Extracts from/by/via/for, bracket IPs, and flags
    provider relay hops so callers can *skip* them instead of trusting them."""
    hops: list[Hop] = []
    # Reverse so index 0 == oldest hop (bottom of the header block).
    for seq, raw in enumerate(reversed(received_lines or [])):
        one = " ".join(raw.split())
        hop = Hop(sequence=seq, raw=one)
        hop.timestamp = _hop_timestamp(one)

        m_from = re.search(r"\bfrom\s+(?P<rest>.*)", one, re.IGNORECASE)
        if m_from:
            rest = m_from.group("rest")
            hop.from_host = _first_host(rest)
            lbl = re.match(r"[^\s(]+\s*\((?P<label>[^)]{0,200})\)", rest)
            if lbl:
                hop.from_label = lbl.group("label").strip()
            m_ip = IP_IN_BRACKETS.search(rest) or IP_BARE.search(rest.split("by")[0])
            if m_ip:
                hop.ip, hop.ip_field = m_ip.group(1), "from"
        m_by = re.search(r"\bby\s+(?P<rest>[^;]{0,240})", one, re.IGNORECASE)
        if m_by:
            rest = m_by.group("rest")
            hop.by_host = _first_host(rest)
            m_ip = IP_IN_BRACKETS.search(rest)
            if m_ip:
                if not hop.ip:
                    hop.ip, hop.ip_field = m_ip.group(1), "by"
                elif hop.ip != m_ip.group(1):
                    hop.ip_field += "+by"
        m_for = re.search(r"\bfor\s+<?([A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+)", one, re.IGNORECASE)
        if m_for:
            hop.for_addr = m_for.group(1)
        m_via = re.search(r"\bvia\s+([^;]{1,120})", one, re.IGNORECASE)
        if m_via:
            hop.via = m_via.group(1).strip()

        hop.relay_org = relay_org_for(hop.from_host, hop.by_host, hop.from_label)
        hop.is_webmail_relay = hop.relay_org != ""
        if hop.ip:
            from ..net import classify_ip

            hop.ip_kind = classify_ip(hop.ip)
        hops.append(hop)
    return hops


def _first_host(text: str) -> str:
    text = text.strip()
    m = re.match(r"([A-Za-z0-9._\-]+)", text)
    return _clean_host(m.group(1)) if m else ""


def _hop_timestamp(line: str) -> str:
    m = re.search(r";\s*(.*)$", line)
    return m.group(1).strip() if m else ""


def relay_org_for(*hosts: str) -> str:
    """Return the webmail/provider org if any host on this hop is provider infra."""
    for host in hosts:
        h = (host or "").lower().strip("().[]")
        if not h:
            continue
        for dom, org in RELAY_DOMAINS.items():
            if h == dom or h.endswith("." + dom):
                return org
    return ""


# ─────────────────────────────────────────────────────────────────────────────
# Authentication-Results / Received-SPF
# ─────────────────────────────────────────────────────────────────────────────
_AUTH_MECH_RE = re.compile(r"\b(spf|dkim|dmarc|dkim-adsp|arc|bimi)[ \t]*=[ \t]*(?P<result>\w+)", re.IGNORECASE)
_IP_KEYS = ("client-ip", "x-clientip", "clientip", "receiver")
_DOMAIN_KEYS = ("dmarc-domain", "header.i=", "smtp.mail-from", "envelope-from")


def parse_auth_results(values: list[str]) -> list[dict[str, Any]]:
    """Extract per-verification-result records, including `client-ip=` which often
    survives even when Received: hops were rewritten by the provider."""
    out: list[dict[str, Any]] = []
    for value in values or []:
        rec: dict[str, Any] = {"raw": re.sub(r"\s+", " ", value).strip()[:900]}
        for m in _AUTH_MECH_RE.finditer(value):
            mech = m.group(1).lower().replace("-", "_")
            rec[mech] = m.group("result").lower()
        for key in _IP_KEYS:
            m = re.search(rf"{re.escape(key)}[ \t]*=[ \t]*\[?(\d{{1,3}}(?:\.\d{{1,3}}){{3}})\]?", value, re.IGNORECASE)
            if m:
                rec["client_ip"] = m.group(1)
                rec["client_ip_key"] = key
                break
        if "client_ip" not in rec:
            # Microsoft/Postfix write it as prose: "spf=fail (sender IP is 1.2.3.4)"
            m = re.search(r"sender\s+IP\s+is\s+\[?(\d{1,3}(?:\.\d{1,3}){3})\]?", value, re.IGNORECASE)
            if m:
                rec["client_ip"] = m.group(1)
                rec["client_ip_key"] = "sender IP is"
        for key in _DOMAIN_KEYS:
            m = re.search(rf"{re.escape(key)}[ \t]*=[ \t]*([^;\s]+)", value, re.IGNORECASE)
            if m:
                rec.setdefault("domain", m.group(1).strip("<>"))
        # method/selector context lines like "identity=mailfrom"
        m = re.search(r"identity[ \t]*=[ \t]*(\w+)", value, re.IGNORECASE)
        if m:
            rec["identity"] = m.group(1).lower()
        m = re.search(r"header\.d=[ \t]*([^;\s]+)", value, re.IGNORECASE)
        if m:
            rec["d"] = m.group(1)
        m = re.search(r"selector=[ \t]*([^;\s]+)", value, re.IGNORECASE)
        if m:
            rec["selector"] = m.group(1)
        if len(rec) > 1:
            out.append(rec)
    return out


def parse_received_spf(values: list[str]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for value in values or []:
        v = re.sub(r"\s+", " ", value).strip()
        m = re.match(r"^(pass|fail|softfail|neutral|none|temperror|permerror|unknown)\b", v, re.IGNORECASE)
        rec: dict[str, Any] = {"raw": v[:600]}
        if m:
            rec["result"] = m.group(1).lower()
        for key in ("client-ip", "client-enrised-ip"):
            mm = re.search(rf"{key}[ \t]*=[ \t]*\[?(\d{{1,3}}(?:\.\d{{1,3}}){{3}})\]?", v, re.IGNORECASE)
            if mm:
                rec["client_ip"] = mm.group(1)
                break
        mm = re.search(r"boundary[ \t]*=[ \t]*([^;\s]+)", v, re.IGNORECASE)
        if mm:
            rec["boundary"] = mm.group(1)
        out.append(rec)
    return out


def parse_dkim_signature(header_value: str) -> dict[str, Any]:
    """Parse the DKIM-Signature tag list (v=, a=, d=, s=, bh=, b=) — enough to
    report which selector to query and whether the signature uses `a=rsa-sha256`."""
    rec: dict[str, Any] = {}
    if not header_value:
        return rec
    for tag in re.findall(r"\b([vbhsladqpktx])=([^;]+)", header_value):
        key, value = tag[0], tag[1].strip().replace(" ", "")
        rec.setdefault(key, value)
    return {
        "version": rec.get("v", ""),
        "algorithm": rec.get("a", ""),
        "domain": rec.get("d", ""),
        "selector": rec.get("s", ""),
        "body_hash": rec.get("bh", "")[:16] + "…" if rec.get("bh") else "",
        "present": True,
    }


# ─────────────────────────────────────────────────────────────────────────────
# Date offset
# ─────────────────────────────────────────────────────────────────────────────
def _tz_offset_minutes(date_str: str) -> int:
    m = OFFSET_RE.search(date_str.strip())
    if not m:
        return 0
    sign, hh, mm = m.group(1), int(m.group(2)), int(m.group(3))
    total = hh * 60 + mm
    return -total if sign == "-" else total


def tz_hint(minutes: int) -> dict[str, Any]:
    """(c) Date-header timezone as a SOFT geographic hint — never a pin."""
    if not minutes:
        return {"present": False, "note": "no numeric offset in Date header"}
    key = f"{'+' if minutes > 0 else '-'}{abs(minutes) // 60:02d}{abs(minutes) % 60:02d}"
    region, conf = TZ_OFFSET_HINTS.get(key, ("unmapped offset", "very-low"))
    return {"present": True, "offset": key, "hours": round(minutes / 60, 2),
            "candidate_region": region, "strength": conf}


# ─────────────────────────────────────────────────────────────────────────────
# Bodies / attachments
# ─────────────────────────────────────────────────────────────────────────────
def extract_bodies(msg: Any) -> tuple[str, str, list[dict[str, Any]]]:
    text_parts: list[str] = []
    html_parts: list[str] = []
    attachments: list[dict[str, Any]] = []

    for part in msg.walk():
        if part.is_multipart():
            continue
        disposition = (part.get_content_disposition() or "").lower()
        filename = part.get_filename() or ""
        ctype = (part.get_content_type() or "").lower()
        payload = part.get_payload(decode=True) or b""
        is_inline_object = bool(part.get("Content-ID")) and ctype.startswith(("image/", "application/"))
        binary_part = ctype not in {"text/plain", "text/html", "multipart/alternative"} and bool(payload)
        if filename or disposition == "attachment" or (is_inline_object and binary_part):
            attachments.append({
                "filename": filename or f"part-{len(attachments) + 1}.bin",
                "content_type": ctype,
                "encoding": (part.get("Content-Transfer-Encoding") or "binary").lower(),
                "size_declared": len(payload),
                "payload": payload,          # raw bytes, kept in memory; only the
                "content_id": (part.get("Content-ID") or "").strip("<>"),
            })
            continue
        decoded = _decode_text(payload, part.get_content_charset() or "utf-8")
        if ctype == "text/html":
            html_parts.append(decoded)
        elif ctype == "text/plain":
            text_parts.append(decoded)
        elif decoded.strip():
            text_parts.append(decoded)
    return "\n".join(text_parts).strip(), "\n".join(html_parts).strip(), attachments


def _decode_text(payload: bytes, charset: str) -> str:
    try:
        return payload.decode(charset, "replace")
    except (LookupError, TypeError):
        return payload.decode("utf-8", "replace")


def html_to_text(html: str) -> str:
    text = re.sub(r"(?is)<(script|style)[^>]*>.*?</\1>", " ", html or "")
    text = re.sub(r"(?i)<br\s*/?>|</(p|div|tr|li|h[1-6])>", "\n", text)
    text = re.sub(r"<[^>]+>", " ", text)
    text = (text.replace("&nbsp;", " ").replace("&amp;", "&").replace("&lt;", "<").replace("&gt;", ">")
                .replace("&#39;", "'").replace("&quot;", '"'))
    return re.sub(r"[ \t]{2,}", " ", text)


def extract_url_pairs(html_body: str, text_body: str) -> list[dict[str, str]]:
    """Return [{url, visible_text}] — anchor href + its displayed text (the pair we
    compare against each other for brand mismatch) plus every bare URL in text."""
    pairs: list[dict[str, str]] = []
    for m in re.finditer(r"(?is)<a\b[^>]*?href\s*=\s*[\"']([^\"']+)[\"'][^>]*>(.*?)</a>", html_body or ""):
        href, inner = m.group(1).strip(), re.sub(r"(?is)<[^>]+>", "", m.group(2))
        pairs.append({"url": href, "visible_text": html_to_text(inner).strip()})
    # Logos are the other half of "visible brand": an <img> carries no anchor text, but
    # its alt/title is what the sender claims the picture *is* ("PayPal"), so we surface
    # it as the visible label. A logo hosted off-brand is exactly the phishing pattern the
    # brief asks us to catch, and "[image] PayPal" gives brand matching something to compare.
    for m in re.finditer(r"(?is)<img\b[^>]*?src\s*=\s*[\"']([^\"']+)[\"'][^>]*>", html_body or ""):
        tag = m.group(0)
        label = ""
        for attr in ("alt", "title"):
            hit = re.search(rf"(?is)\b{attr}\s*=\s*[\"']([^\"']*)[\"']", tag)
            if hit:
                label = html_to_text(hit.group(1)).strip()
                break
        pairs.append({"url": m.group(1).strip(), "visible_text": f"[image] {label}".strip()})
    for m in URL_RE.finditer(text_body or ""):
        url = (m.group(1) or m.group(2) or "").rstrip(".,);")
        if url and not any(p["url"] == url for p in pairs):
            pairs.append({"url": url, "visible_text": ""})
    return pairs


# ─────────────────────────────────────────────────────────────────────────────
# Brand / homoglyph analysis (shared with extract_urls tool)
# ─────────────────────────────────────────────────────────────────────────────
def normalize_homoglyphs(text: str) -> str:
    out = []
    for ch in text or "":
        out.append(HOMOGLYPHS.get(ch, ch))
    return "".join(out)


def has_homoglyphs(text: str) -> bool:
    return any((ch in HOMOGLYPHS) or (ord(ch) > 0x2000 and ch.isalpha()) for ch in text or "")


def brand_for_text(text: str) -> str:
    low = (text or "").lower()
    for brand, spec in BRANDS.items():
        for phrase in spec["phrases"]:
            if phrase in low:
                return brand
    return ""


def brand_domains_for(brand: str) -> set[str]:
    return set(BRANDS.get(brand, {}).get("domains", set()))


def registrable_domain(host: str) -> str:
    """Cheap eTLD+1 for known-suffix collisions (good enough for brand matching;
    we deliberately avoid a PSL dependency and say so when it matters)."""
    host = (host or "").strip(".").lower()
    if not host:
        return ""
    parts = host.split(".")
    if len(parts) <= 2:
        return host
    second = ".".join(parts[-2:])
    if second.split(".")[-1] in {"co", "com", "net", "org", "gov", "ac", "edu"} and len(parts[-1]) == 2:
        return ".".join(parts[-3:])
    return second


def extension_mismatch(filename: str, magic_type: str) -> bool:
    """(tool 7) File-type mismatch, e.g. MZ/PE bytes named invoice.pdf."""
    ext = ("." + filename.lower().rsplit(".", 1)[-1]) if "." in filename else ""
    m = (magic_type or "").lower()
    table = {
        ".pdf": ("pdf",), ".exe": ("pe32", "pe32+", "windows executable", "dos"),
        ".doc": ("Composite Document File", "office openxml"), ".docx": ("Zip", "Office Open XML"),
        ".xls": ("Composite Document File",), ".xlsx": ("Zip", "Open XML"),
        ".zip": ("Zip", "archive"), ".jpg": ("JPEG",), ".jpeg": ("JPEG",),
        ".png": ("PNG",), ".gif": ("GIF",), ".txt": ("text", "ASCII", "Unicode"),
        ".htm": ("HTML", "text"), ".html": ("HTML", "text"),
    }
    allowed = table.get(ext)
    if not allowed or not m:
        return False
    return not any(a.lower() in m for a in allowed)


def entropy_bits_per_byte(data: bytes) -> float:
    """Shannon entropy over the first 1 MiB — high (>7.2) suggests packed or
    encrypted payloads, i.e. content that a scanner can't see into."""
    import math
    from collections import Counter

    if not data:
        return 0.0
    sample = data[: 1024 * 1024]
    counts = Counter(sample)
    total = len(sample)
    ent = -sum((c / total) * math.log2(c / total) for c in counts.values())
    return round(ent, 3)


def structural_notes(parsed: ParsedEmail) -> list[str]:
    notes: list[str] = []
    fr = parsed.envelope.get("from", "")
    rt = parsed.envelope.get("reply-to", "")
    rp = parsed.envelope.get("return-path", "")
    if rt and domain_of(addr_of(rt)) and domain_of(addr_of(rt)) != domain_of(addr_of(fr)):
        notes.append(f"Reply-To domain '{domain_of(addr_of(rt))}' differs from From domain '{domain_of(addr_of(fr))}'")
    if rp and domain_of(addr_of(rp)) and domain_of(addr_of(rp)) != domain_of(addr_of(fr)):
        notes.append(f"Return-Path domain '{domain_of(addr_of(rp))}' differs from From domain '{domain_of(addr_of(fr))}'")
    disp = display_name_of(fr)
    brand = brand_for_text(disp)
    if brand and domain_of(addr_of(fr)) not in brand_domains_for(brand):
        notes.append(f"Display name claims brand '{brand}' but sender domain is '{domain_of(addr_of(fr))}'")
    if not parsed.received_raw:
        notes.append("no Received: headers present — origin tracing is impossible from this file")
    if parsed.tz_minutes:
        notes.append(f"Date offset {parsed.tz_offset} ({tz_hint(parsed.tz_minutes)['candidate_region']})")
    return notes


def decode_payload_base64(text: str) -> bytes:
    """Used by the sample generator/tests only."""
    return base64.b64decode(quopri.decodestring(text.encode()) or text.encode())
