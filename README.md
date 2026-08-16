# ScamWatch

A single-file watcher for fake "live support" / screen-sharing scam landing
pages — the tech-support fraud ecosystem.

It fights the operation on the axis that actually costs them: burning domains
and phone numbers before victims land on them, with evidence packages
auto-formatted for the people who can kill the accounts.

**Author:** CypherNova1337 · Tool used by VoidSec

---

## Why a watcher and not something louder

These operations re-register a domain in about two minutes. Anything that
targets a single host loses that race by design. What does not lose is
continuous observation plus fast, well-formed abuse reports — and above all
**phone numbers**, which are the durable indicator. A domain costs them a
dollar and five minutes. A burned call-centre number costs them days, and
mule-account freezes are where arrests actually happen.

## How it works

1. **Certificate Transparency (crt.sh)** — catches freshly-certed lookalike
   domains the moment they are minted (`*-windows-defender-*`, `live-support-*`,
   bank shortcodes). Queries are deliberately **broad** and refined locally;
   see the crt.sh note under Limitations for why that matters.
2. **urlscan.io search** — pulls scans matching known kit signatures
   (`config.js` + `SUPABASE_URL`/`ACCESS_KEY`, the ANZ cluster, the free-host
   clusters).
3. **Public phishing feeds** — OpenPhish and Phishing.Database, filtered down
   to the tech-support keyword set. No API key required. These carry the pass
   when crt.sh is overloaded, which is often.
4. **Fingerprint pass** — one ordinary HTTP GET, exactly what a browser sends.
   Scores the page against markers (AnyDesk / TeamViewer / ScreenConnect
   install prompts, fake AV alerts, bank impersonation) and extracts the phone
   numbers. Disable entirely with `--no-fingerprint`.
5. **Attribution and packaging** — RDAP (no API key) for registrar and network,
   abuse-address lookup, then a Markdown report plus a ready-to-send `.eml`
   draft per confirmed domain.

## Install

```bash
git clone https://github.com/CypherNova1337/ScamWatch
cd ScamWatch
pip install -r requirements.txt
```

Python 3.9+. The only dependency is `requests`.

## Run

```bash
python3 scamwatch.py --once -v                  # one pass, fingerprints candidates
python3 scamwatch.py --loop --interval 300      # permanent watcher
python3 scamwatch.py --no-fingerprint --loop    # fully passive, no GETs at all
python3 scamwatch.py --dry-run -v               # detect and score, write nothing
python3 scamwatch.py --stats                    # what the database knows so far
```

Set `URLSCAN_API_KEY` for better urlscan rate limits and full search coverage.
It runs without one.

### Useful flags

| Flag | Effect |
|---|---|
| `--no-ct` / `--no-urlscan` / `--no-feeds` | disable an individual source |
| `--no-fingerprint` | never contact candidates; records names only |
| `--dry-run` | full detection, no files written |
| `--force` | reprocess domains already in the database |
| `--limit N` | max results per source query (default 50) |
| `--delay N` | seconds between candidate fetches (default 0.5) |
| `--out` / `--db` / `--config` | relocate outputs and state |

## What comes out

In `out/`:

- `<ts>_<domain>.md` — full evidence report per confirmed domain
- `<ts>_<domain>.eml` — addressed, ready-to-review abuse-desk draft
- `scamwatch.csv` — one row per confirmation, the campaign timeline
- `iocs_phones.csv` — **the master IOC sheet**: every extracted number, first
  and last seen, and every domain it appeared on

That last file is the point. Numbers recur across domains, so the sheet
correlates otherwise-unlinked infrastructure into single campaigns. Batch it to
I4C (`cybercrime.gov.in`) and IC3 rather than reporting one domain at a time.

## Deploy as a service

```ini
# /etc/systemd/system/scamwatch.service
[Unit]
Description=ScamWatch takedown watcher
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
WorkingDirectory=/opt/scamwatch
ExecStart=/usr/bin/python3 /opt/scamwatch/scamwatch.py --loop --interval 300 \
          --out /var/lib/scamwatch/out --db /var/lib/scamwatch/scamwatch.db \
          --config /etc/scamwatch/scamwatch.json
Restart=always
RestartSec=30
StateDirectory=scamwatch
Environment=URLSCAN_API_KEY=

# hardening: it only needs outbound HTTPS and its own state directory
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ProtectKernelTunables=true
ProtectControlGroups=true
RestrictAddressFamilies=AF_INET AF_INET6
ReadWritePaths=/var/lib/scamwatch

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl enable --now scamwatch
journalctl -u scamwatch -f
```

## Configuration

First run writes `scamwatch.json`. Your edits are merged over the built-in
defaults, so upgrades pick up new keys without wiping your changes.

Keys worth knowing:

- `ct_query_terms` — what is actually sent to crt.sh. Keep these broad and
  cheap; highest-yield first, since the circuit breaker may cut a pass short
- `ct_keywords`, `brand_shortcodes` — local refinement, matched against
  hostnames a broad query already returned. Never sent to crt.sh directly
- `urlscan_queries` — `[label, query]` pairs, kit signatures
- `feed_urls` — `[label, url]` pairs of keyless phishing feeds
- `feed_min_interval` — seconds between feed re-downloads (default 3600). The
  feeds are multi-megabyte files served for free; they are also revalidated
  with `ETag`/`If-Modified-Since`, so a `--loop` at 300s does not re-pull them
  on every pass
- `allowlist` — **read this before tuning anything else** (below)
- `confirm_threshold` — **content** score needed before a report is written.
  The domain-name heuristic is scored separately and deliberately excluded
- `reporter_from`, `reporter_org` — your identity, stamped into `.eml` drafts

## Operating notes — read before you send anything

**Nothing is ever mailed automatically.** The tool writes drafts. A human reads
them and sends them. That is deliberate and you should keep it that way.

**A false positive is worse than a miss.** Reporting a legitimate business to
its registrar can take a real site offline. Three guards exist:

1. **The allowlist.** Legitimate vendors, banks, and every `.gov` / `.edu` /
   `.mil` / `.police.uk`-class suffix are never reported, regardless of what a
   keyword search turns up — `%windows-defender%` on crt.sh matches genuine
   Microsoft certificates. Extend `allowlist` freely; it is cheap insurance.
2. **Confirmation requires served content.** Each candidate carries two
   separate scores: a *name heuristic* (ranking hint) and a *content score*
   (what the server actually served). Only the content score is compared
   against `confirm_threshold`, so a name like `windows-defender-alert.sbs`
   can never top up one weak marker into a confirmation. A non-2xx response
   also never confirms — a 403/451 takedown stub is not evidence.

   This is not hypothetical: during testing, a live page whose only marker was
   `error code` reached a combined score of 6 (half of it from the domain name)
   and was reported. It scores 3 against the current gate and is rejected.
3. **`--dry-run`.** Use it whenever you change scoring or keywords.

**Verify each report before sending.** Open the page yourself, or check the
urlscan link in the report. The `.eml` is a draft, not a verdict.

## Limitations, stated honestly

- **crt.sh is unreliable, and its failures are silent.** Measured directly:
  `%defender%` returned 2233 rows while `%windows-defender%` returned an empty
  array on one attempt and a 502 minutes later. An empty array is *not*
  evidence of absence — it is often the server giving up on an expensive
  pattern. Two consequences are built in: queries are broad by default
  (`ct_query_terms`) and refined locally, and every pass prints a `sources:`
  line with each source's health plus a count of keywords that came back
  empty. A dead source reads `FAILED`; it never just goes quiet. A circuit
  breaker also stops the pass hammering crt.sh after 5 consecutive failures,
  so an outage cannot stall a pass past its own loop interval.
- **`--no-fingerprint` writes no reports.** It cannot: confirmation requires
  looking at the page. Passive mode records names for later review only.
- **Phone canonicalisation is best-effort.** Numbers are normalised to E.164
  where the country is knowable (NANP and hinted national formats merge
  correctly). A bare national-format number from an unknown country is kept
  as-is and may not merge with its international form.
- **Registrable-domain detection uses a bundled suffix list**, not the full
  Public Suffix List. It is accurate for the TLDs in `MULTI_PART_SUFFIXES` and
  falls back to last-two-labels elsewhere.
- **Scoring is heuristic.** It is tuned to be specific rather than sensitive.
  Expect to miss pages that are pure image or that render entirely via
  JavaScript — there is no browser here, only an HTTP GET.

## Reporting channels

| Channel | Where |
|---|---|
| US — IC3 | https://www.ic3.gov |
| US — FTC | https://reportfraud.ftc.gov |
| UK — Action Fraud | https://www.actionfraud.police.uk |
| India — I4C / 1930 | https://cybercrime.gov.in |
| Australia — Scamwatch | https://www.scamwatch.gov.au |
| Malicious URL feed | https://urlhaus.abuse.ch |

## Tests

```bash
python3 -m unittest -v
```

The suite covers the parts where a mistake has a real cost: the allowlist,
phone extraction and canonicalisation, the confirmation gate, RDAP parsing of
malformed vCards, and state handling.

## Scope

This is a defensive observation and abuse-reporting tool. It reads public
sources and fetches public pages. It contains no exploitation capability, and
it should not grow any.
