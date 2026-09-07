# Sample corpus — read this before demoing

All four `.eml` files are **fabricated for demonstration**. They are not real
attacks, and every network reference inside them is intentionally harmless:

| reference used | why it is safe |
|---|---|
| `127.0.0.1`, `127.0.0.53` | loopback — cannot reach anything |
| `192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24` | RFC5737 *documentation* ranges — unroutable by definition |
| `example.com`, `*.example`, `*.invalid`, `*.ltd` (fake) | RFC2606/RFC6761 reserved or non-resolving names |
| `payloads/*.bin` | text/random bytes; `eicar_com.txt` is the industry's harmless AV *test string* |

Consequence: to make tracing deterministic in an air-gapped venue, the agent must
be allowed to look up these non-routable addresses, which is exactly what
`--geoip-allow-private` and `samples/fixtures/dns_fixtures.json` are for. Never
point those at a real investigation where you want honest "this IP is not
traceable" answers.

| file | what it exercises | what you should see (measured here: `--demo --no-llm`, mock APIs, fixtures) |
|---|---|---|
| `clean_newsletter.eml` | honest sender, SPF/DKIM/DMARC pass, brand-matching https link, origin from a documentation-range hop stamped by the receiver | **SAFE** · risk 23.5 · confidence 76.5 % · `exit 0` · `origin=192.0.2.10 kind=spf_client_ip ceiling=78%` |
| `phishing_obvious.eml` | typosquat + punycode/homoglyph host, IP-literal http URL, `dmarc=fail`, `file_type_mismatch`, high-entropy "invoice.pdf", EICAR via VT hash, `<EMAIL_DATA>` breakout attempt in an HTML comment | **MALICIOUS** · risk 99.0 · confidence 90.1 % · `exit 2` · gate asked before `static_file_scan` · injection attempt logged, not obeyed |
| `gmail_bec_subtle.eml` | **Gmail webmail sender**: only Google relay IPs (`client-ip=74.125.20.46` is Google's own edge) → personal IP unrecoverable; Message-ID `@mail.gmail.com`, `+0530` date offset, Reply-To domain mismatch, lure-domain trace, polite-but-archaic style | **SUSPICIOUS** · risk 33.1 · confidence 72.4 % · `exit 1` · `origin=UNRECOVERABLE kind=phishing_infrastructure ceiling=62%` (the *lure* IP 203.0.113.88 is reported instead, explicitly labelled as attacker infrastructure) · no fake pin |
| `tor_exit_legit.eml` | origin on a (fixture-simulated) Tor exit; SPF/DKIM/DMARC all pass; content is a whistleblower-style note with no URLs | **SAFE** · risk 23.8 · confidence 86.3 % · `exit 0` · prints `tor_exit ▲ +52` **and** the sentence "origin anonymized — elevated scrutiny, NOT proof of guilt"; authenticating mail with no lure stays under the SUSPICIOUS floor |

The last row is the point of the whole corpus: rule 6 says flag and scrutinise, **not**
condemn. A Tor exit contributes `+2.20` of risk — enough to be heard, not enough to convict a
message that authenticates cleanly and asks for nothing. (`classify()` calls ≥ 30 SUSPICIOUS and
≥ 65 MALICIOUS *only* with at least one strong indicator, so soft hints alone can never convict.)

## Demo one-liner (fully offline, deterministic)
```bash
python -m cybersecurity_agent mock-apis --port 8099 &
SENTINEL_DNS_FIXTURES=samples/fixtures/dns_fixtures.json \
SENTINEL_TOR_EXIT_FIXTURE=samples/fixtures/tor_exit_ips.txt \
python -m cybersecurity_agent investigate samples/gmail_bec_subtle.eml \
  --demo --geo-base-url http://127.0.0.1:8099 --reputation-base-url http://127.0.0.1:8099 \
  --geoip-allow-private
```
`tor_exit_ips.txt` makes `check_tor_exit` report a hit **labelled `simulated`** —
with no fixture, the tool falls back to the live Tor DNSEL query and (in a normal
network) correctly reports "not a listed Tor exit".
