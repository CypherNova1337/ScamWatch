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
2. **urlscan.io search** — pulls recent scans matching known kit signatures
   (`config.js` + `SUPABASE_URL`/`ACCESS_KEY`, the ANZ cluster, remote-tool
   lures on free hosts). Every query is constrained to the last
   `urlscan_max_age_days`, and each hit carries its scan UUID so archived
   evidence can be recovered later.
3. **Public phishing feeds** — OpenPhish and Phishing.Database, filtered down
   to the tech-support keyword set. No API key required. These carry the pass
   when crt.sh is overloaded, which is often.
4. **Fingerprint pass** — one ordinary HTTP GET, exactly what a browser sends.
   Scores the page against markers (AnyDesk / TeamViewer / ScreenConnect
   install prompts, fake AV alerts, bank impersonation) and extracts the phone
   numbers. Disable entirely with `--no-fingerprint`.
5. **Archived-evidence fallback** — when the live page has already been pulled
   (the common case), urlscan's saved DOM is scored instead. Reports state
   which of the two the evidence came from, in both the Markdown and the
   email draft, so an abuse desk is never told you saw something live that
   you did not.
6. **Attribution and packaging** — RDAP (no API key) for registrar and network,
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

**Set `URLSCAN_API_KEY`.** It is documented elsewhere as optional; in practice
it is close to required. Without it, urlscan's saved-DOM endpoint and result
API both answer `{"warning": "You're not logged in!"}`, which disables the
archived-evidence fallback — and that fallback is what lets the tool confirm
anything at all against pages that are already gone. See Limitations. A free
account key is enough. The tool still runs without one; it will just find far
more corpses than evidence, and it warns you when it does.

### Useful flags

| Flag | Effect |
|---|---|
| `--no-ct` / `--no-urlscan` / `--no-feeds` | disable an individual source |
| `--no-fingerprint` | never contact candidates; records names only |
| `--dry-run` | full detection, no files written |
| `--force` | reprocess domains already in the database |
| `--limit N` | max results per source query (default 50) |
| `--delay N` | seconds between candidate fetches (default 0.5) |
| `--max-seconds N` | wall-clock budget for candidate processing; the rest return next pass |
| `--out` / `--db` / `--config` | relocate outputs and state |

## What comes out

Findings land in one of two tiers. **This tool never addresses an abuse report
on its own reading of a page** — see Precision below for the measurement that
forced that rule.

| Tier | Requires | Output |
|---|---|---|
| `confirmed` | content gate **and** an independent signal (urlscan verdict, phishing-feed listing) | full report + addressed `.eml` |
| `review` | content gate only | short note in `out/review/`, no draft |

In `out/`:

- `<ts>_<domain>.md` — full evidence report per confirmed domain
- `<ts>_<domain>.eml` — addressed, ready-to-review abuse-desk draft
- `review/<ts>_<domain>.md` — an uncorroborated lead for a human to check
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
- `ct_terms_per_pass` — how many CT terms to query per pass (default 4).
  Rotates, so all terms are covered every few passes while any single pass
  stays bounded
- `ct_time_budget` — hard ceiling in seconds on the CT phase (default 180)
- `ct_failure_rate` / `ct_failure_min_queries` — give up on crt.sh when this
  fraction of queries is failing. Consecutive-failure detection alone missed
  the interleaved mode, which is the expensive one
- `ct_require_refine` — default `true`: a hostname must match one of the
  refinement keywords to become a candidate. Broad terms bring noise with them
  (`%defender%` returns Land Rover dealerships), and this is what keeps the
  results specific. `--limit` counts domains kept, not rows scanned, so this
  costs no recall
- `urlscan_queries` — `[label, query]` pairs, kit signatures. Make them carry
  real signal: a bare `page.url:"support"` filter was tried and matched a
  German Minecraft donation page
- `urlscan_max_age_days` — scans older than this are ignored (default 7)
- `urlscan_use_archive` — score urlscan's saved DOM when the live page is
  gone (default `true`, needs `URLSCAN_API_KEY`)
- `feed_urls` — `[label, url]` pairs of keyless phishing feeds
- `feed_min_interval` — seconds between feed re-downloads (default 3600). The
  feeds are multi-megabyte files served for free; they are also revalidated
  with `ETag`/`If-Modified-Since`, so a `--loop` at 300s does not re-pull them
  on every pass
- `allowlist` — **read this before tuning anything else** (below)
- `vendor_labels` — brand labels exempt on any TLD, so a vendor's ccTLD sites
  are never reported
- `confirm_threshold` — **content** score needed to pass the content gate. The
  domain-name heuristic is scored separately and deliberately excluded
- `require_corroboration` — default `true`. Turning it off means mailing abuse
  desks on this tool's own reading of a page, which measured 0/7
- `reporter_from`, `reporter_org` — your identity, stamped into `.eml` drafts

## Precision, as measured

Scored against 98 live pages pulled from urlscan, with each gate added in turn:

Two labelled sets were used: pages found by broad topic queries (which turned
out to be legitimate) and pages found by the kit's own artifacts (which turned
out to be real scams).

| Gate | False positives | Real scams caught |
|---|---|---|
| Content markers only | 7 | — |
| \+ editorial / business veto | 0 | 3 of 5 |
| \+ impersonation override | **0** | **5 of 5** |

The seven were two blog posts about malware, a security vendor's advisory on
AnyDesk phishing, and four genuine computer repair businesses. Every one of
them legitimately says "your computer is infected" and "we use AnyDesk". Run
as originally written, the tool would have mailed abuse desks about all seven.

The seven were two blog posts about malware, a security vendor's advisory on
AnyDesk phishing, and four genuine computer repair businesses — all of which
legitimately say "your computer is infected" and "we use AnyDesk".

The confirmed scams were found a different way, and that difference is the
main lesson: **searching for the topic finds legitimate sites, searching for
the kit finds scams.** `filename:"beep.mp3"` — the alarm loop these pages play
— surfaced five confirmed scam pages, among them `windows-defender-alert.com`
("Windows Security - CRITICAL ALERT", score 29, toll-free number, corroborated
by urlscan). Topic keywords surfaced repair shops. Both query styles are free
tier; only one of them works.

The veto initially cut too deep in the other direction, rejecting two real
scams: one titled "Security Center" carrying a toll-free number was vetoed
because it included "privacy policy", "about us" and "terms of service" —
wording kits copy precisely in order to look legitimate. Hence the
impersonation override: a page may *discuss* Windows Defender, and a business
may sell repairs, but only a scam presents itself *as* Defender while claiming
a detection about you or pushing a number to call.

Treat `review` notes as leads and `confirmed` reports as drafts. Read the page
before you send anything.

### What the urlscan tier does and does not allow

With a free account key, **reading** a scan's verdict works — verified live,
returning `malicious`, `score=100` and `tag=phishing` on real phishing pages —
so corroboration functions as designed. **Searching** on verdict fields
(`verdicts.overall.malicious`, `verdicts.overall.tags`) returns HTTP 403,
`"Your current plan does not allow you to search field ..."`. So urlscan's
judgement can confirm a candidate this tool already found, but cannot be used
to go looking for candidates. That is why corroboration is applied at scoring
time rather than as a search filter, and it is the reason no corroborated
tech-support scam could be exhibited during development: the queries that
would find one directly are gated behind a paid plan.

## Operating notes — read before you send anything

**Nothing is ever mailed automatically.** The tool writes drafts. A human reads
them and sends them. That is deliberate and you should keep it that way.

**A false positive is worse than a miss.** Reporting a legitimate business to
its registrar can take a real site offline. Four guards exist:

1. **The allowlist.** Legitimate vendors, banks, and every `.gov` / `.edu` /
   `.mil` / `.police.uk`-class suffix are never reported, regardless of what a
   keyword search turns up — `%windows-defender%` on crt.sh matches genuine
   Microsoft certificates. Extend `allowlist` freely; it is cheap insurance.

   `vendor_labels` handles the harder half. Vendors run their brand across
   many ccTLDs and an exact-domain list cannot keep up: a live pass returned
   `teamviewer.cn` and five of its subdomains, which is TeamViewer's real
   China operation — and a genuine TeamViewer page trips
   `teamviewer` + `remote control` + `session id` = 7, clearing the gate on
   its own. Anything whose registrable label *is* a vendor brand is exempt on
   any TLD. The cost is a miss if someone registers a brand exactly
   (`teamviewer.xyz`); the benefit is never mailing an abuse desk about the
   vendor's own site. Lookalikes do not use the bare label —
   `anydesk--app.online` and `anydesk-win.y--a--hoo.com` both still come
   through.
2. **Confirmation requires served content.** Each candidate carries two
   separate scores: a *name heuristic* (ranking hint) and a *content score*
   (what the server actually served). Only the content score is compared
   against `confirm_threshold`, so a name like `windows-defender-alert.sbs`
   can never top up one weak marker into a confirmation. A non-2xx response
   also never confirms — a 403/451 takedown stub is not evidence.

   This is not hypothetical: during testing, a live page whose only marker was
   `error code` reached a combined score of 6 (half of it from the domain name)
   and was reported. It scores 3 against the current gate and is rejected.
3. **At least one strong marker is required.** Reaching the threshold by
   stacking weak signals is not enough. A live pass surfaced
   `suncoastcreditunion.com`, a real credit union — and a legitimate
   security-awareness page can carry `security alert` + `your password` +
   `call the number`, which is exactly the threshold. Confirmation now needs a
   marker that describes something only a scam page does: an AnyDesk install
   prompt, `virus detected`, `do not restart your computer`.
4. **`--dry-run`.** Use it whenever you change scoring or keywords.

**Verify each report before sending.** Open the page yourself, or check the
urlscan link in the report. The `.eml` is a draft, not a verdict.

## Limitations, stated honestly

- **crt.sh is unreliable, and a *working* crt.sh is what costs time.** Measured
  over 15 consecutive passes and a latency probe: a query that **fails**
  returns in **0.15s**, while a query that **succeeds** takes **~34s**. So the
  slow passes are the healthy ones. Every fast pass in the soak (221s, 234s,
  252s) was one where crt.sh was down and the breaker cut it short; every pass
  where crt.sh worked ran 400-600s. Shortening the read timeout would
  therefore cut *successful* queries and silently lose coverage — the fix is
  to ask for less per pass, so `ct_terms_per_pass` rotates a few terms at a
  time and completes the list every few passes.
- **crt.sh failure detail.** Measured directly:
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
- **Scoring describes a topic, and a topic is not an intent.** This is the
  detector's central weakness and it was measured, not guessed. Scored against
  98 live pages, topic-only matching confirmed seven — and all seven were
  false positives: two blog posts about malware, a security vendor's advisory
  on AnyDesk phishing, and four genuine computer repair businesses. Every one
  of them legitimately says "your computer is infected" and "we use AnyDesk".
  Editorial and business signals now veto those pages, but the underlying
  limitation stands: matching vocabulary cannot by itself distinguish a scam
  page from a page about scams. **Treat every generated report as a lead to
  verify, never as a verdict**, and read the page before you send anything.
- **Scoring is heuristic.** It is tuned to be specific rather than sensitive.
  Expect to miss pages that are pure image or that render entirely via
  JavaScript — there is no browser here, only an HTTP GET.
- **The targets die faster than the sources index them.** This is the single
  biggest constraint on the whole approach. Of 14 urlscan hits fetched during
  testing, 10 returned a hosting "site not found" stub, and the two freshest
  and most on-target — `metrobank-anydesk-support.com.ph` and
  `anydesk-support-metrobank.com.ph`, scanned the previous day — were already
  503 and unreachable. This is why queries are date-constrained and why the
  archived-DOM fallback exists; without an API key to enable that fallback,
  expect most candidates to be dead on arrival.
- **Most feed candidates will never confirm, and that is correct.** The public
  feeds are dominated by credential phishing rather than tech-support fraud;
  in a live pass, 843 candidates produced a single confirmation. The keyword
  filter narrows them, but a page that phishes a bank login is not a
  tech-support scam and the gate rightly refuses to describe it as one. The
  feeds earn their place by carrying the pass when crt.sh is down — if you
  would rather not spend the fingerprint budget, run `--no-feeds`.
- **Candidates are fingerprinted once, when first seen.** A domain that is
  parked at discovery and turns malicious an hour later is not revisited
  unless you pass `--force`. Re-checking known candidates on a slower cycle
  would be the natural next feature.

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
