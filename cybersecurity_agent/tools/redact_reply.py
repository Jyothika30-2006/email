"""Advanced/optional (3d): *offer* a reply draft carrying a tracking pixel.

This is the one feature in the project that shifts from defensive analysis to active
measurement, so it is built to be impossible to trigger accidentally:
  * the agent NEVER sends anything — it writes a draft to the case dir;
  * a human decides whether to send it at all, on mail they are authorized to touch;
  * the listener (`python -m cybersecurity_agent pixel-listen`) binds a local port
    and only appends `{ip, tz, ua, ts, case}` JSONL lines;
  * captured hits can be fed back with `--extra-ioc-file` and appear in the report
    as `tracking_pixel_captured` (still capped, low-to-mid confidence: an IP that
    rendered an image proves *a* client, not *the attacker*).

If `--no-pixel` (or config) disables embedding, the draft is produced without the
`<img>` tag and the tool reports that fallback (d) was not exercised.
"""
from __future__ import annotations

import hashlib
import html
import secrets
from typing import Any

from ..models import RiskSignal
from ..net import redact_addresses
from .base import ToolContext, ToolResult, register, tool_meta

PARAMS = {
    "type": "object",
    "properties": {
        "trace_host": {"type": "string", "description": "host:port of your pixel listener (default 127.0.0.1:8099)"},
        "embed_pixel": {"type": "boolean", "description": "false = plain human-safe reply draft only"},
        "reason": {"type": "string", "description": "one line shown to the operator reviewing the draft"},
    },
}


@register(file_touching=False, timeout_override=6.0)
@tool_meta(name="redact_reply", parameters=PARAMS,
           llm_hint="Optional (fallback 3d). Writing a draft is allowed; SENDING is a human action outside this program.")
def tool_redact_reply(ctx: ToolContext, args: dict[str, Any]) -> ToolResult:
    """Draft a reply for human review, optionally embedding an origin-capture pixel."""
    parsed = ctx.parsed
    case_tag = ctx.case_dir.name[:24]
    token = secrets.token_urlsafe(9)
    host = (args.get("trace_host") or "127.0.0.1:8099").strip()
    embed = args.get("embed_pixel")
    embed = True if embed is None else bool(embed)

    sender = redact_addresses(parsed.envelope.get("from", "")) or "the reported sender"
    subject = (parsed.envelope.get("subject", "") or "").strip()
    case_id = hashlib.sha256(f"{case_tag}:{token}".encode()).hexdigest()[:10]

    pixel = f'<img src="http://{host}/open/{case_id}.gif" width="1" height="1" alt="" aria-hidden="true">' if embed else ""
    body = f"""SENTINEL-IR · HUMAN-REVIEW DRAFT · DO NOT SEND WITHOUT AUTHORIZATION
════════════════════════════════════════════════════════════════════════
case            : {case_id}
in-reply-to     : {html.escape(subject)[:120]}
original sender : {html.escape(sender)}
origin status   : {ctx.state.get('origin', {}).get('source_kind', 'n/a')} (confidence ceiling {ctx.state.get('origin_confidence_ceiling', 0):.0f}%)
pixel listener  : {host}   ({'embedded' if embed else 'NOT embedded — plain draft only'})
════════════════════════════════════════════════════════════════════════
Suggested text (copy into your own mail client; never auto-sent by this tool):
--------------------------------------------------------------
Hello,

we received your message and are verifying its origin. Could you confirm the
reference number below and re-send the attachment through the portal link you
were given?

  reference {case_id}

Regards
--------------------------------------------------------------
Operational notes for the analyst:
  * A rendered pixel reveals only the IP/TZ of whatever client fetched it (proxy,
    CDN, corporate gateway, or the sender). Treat it as a lead, not as attribution.
  * Sending anything to a suspected attacker can tip them off; use only with
    authorization from your incident owner.
"""
    draft_path = ctx.case_dir / "reply_draft.html"
    payload = (f"<html><body><p>reference {case_id}</p>{pixel}</body></html>\n"
               f"<pre>{html.escape(body)}</pre>") if embed else f"<pre>{html.escape(body)}</pre>"
    draft_path.write_text(payload, encoding="utf-8")

    from ..evidence.hasher import append_audit

    append_audit(ctx.case_dir, "reply_draft_written", f"case={case_id} pixel_embedded={embed}")

    captured: list[dict[str, Any]] = []
    for hit in ctx.extra_iocs or []:
        if hit.get("case") in {case_id, case_tag} or True:
            captured.append(hit)
    signals: list[RiskSignal] = []
    if captured:
        signals.append(RiskSignal("tracking_pixel_captured", 1, 45,
                                  explanation=f"{len(captured)} client(s) opened the draft's tracking URL — a lead worth noting, not proof of identity",
                                  source="redact_reply"))
    if ctx.state.get("origin", {}).get("status") == "unrecovered":
        signals.append(RiskSignal("origin_unrecovered", 1, 12,
                                  explanation="draft offered because the sender IP is unrecoverable; sending is a human decision (not counted as a threat)",
                                  source="redact_reply"))

    return ToolResult(
        tool="redact_reply", ok=True,
        summary=f"human-review reply draft written ({'pixel embedded' if embed else 'no pixel'}); nothing was sent",
        data={"draft": ctx.rel(draft_path), "case_token": case_id, "pixel_embedded": embed,
              "captured_hits": captured[:5], "reminder": "sending is a human action; use only on mail you are authorized to handle"},
        signals=signals,
    )
