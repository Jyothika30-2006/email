# Sent to humans, not machines — delete what does not apply, but keep the checkboxes.

## What changed, and why

*One paragraph.* What problem does this fix or add, in terms of behaviour a user would notice?

## Checklist for every pull request

- [ ] `python -m pytest tests -q` passes offline (no network egress, no keys, no Docker, no Ollama)
- [ ] `python -m cybersecurity_agent selftest` prints ✅ (7 checks)
- [ ] `bash scripts/demo.sh --quick` exits 0 — the exit code per sample still matches its verdict
- [ ] any **number written into a doc** was re-measured in this checkout, not copied from an older doc
- [ ] no verdict, threshold, cap, weight or signal was changed to make a test pass
      (if one was, say so in the description and justify it in `FINAL_REPORT.md` §3)
- [ ] `tests/test_docs_are_honest.py` passes — README/ARCHITECTURE/diagrams still match the code
- [ ] new tool ⇒ whitelist entry + `needs` + timeout + a refusal test; nothing that can exec goes anywhere else
- [ ] no web UI, dashboard, browser route or cloud LLM call (rule 2), including "just a little status page"

## Measured output

Paste the real thing — a diff of the four samples' verdict lines, the failing test, the frame:

```
samples/clean_newsletter.eml   → SAFE       risk  …/100   confidence …%   exit 0
samples/phishing_obvious.eml   → MALICIOUS  risk  …/100   confidence …%   exit 2
samples/gmail_bec_subtle.eml   → SUSPICIOUS risk  …/100   confidence …%   exit 1
samples/tor_exit_legit.eml     → SAFE       risk  …/100   confidence …%   exit 0
```

## Notes for the reviewer

- How could this be wrong in a way the tests would not notice?
- What did you deliberately *not* do?
