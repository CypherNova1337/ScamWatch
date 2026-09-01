# ScamWatch

A single-file watcher for fake "live support" and screen-sharing scam pages —
the tech-support fraud ecosystem.

It goes after the part of the operation that actually costs them: burning
domains and, more importantly, **phone numbers**, with evidence packaged for
the abuse desks that can kill the accounts.

**Author:** CypherNova1337 · Tool used by VoidSec · MIT licensed

---

## Why a watcher and not something louder

These operations re-register a domain in about two minutes, so anything aimed
at a single host loses that race by design. What does not lose is continuous
observation plus fast, well-formed abuse reports.

A domain costs a dollar and five minutes. A burned call-centre number costs
weeks. Numbers also recur across campaigns, which is what turns a pile of
unrelated domains into one operation with people behind it.

## Install

```bash
git clone https://github.com/CypherNova1337/ScamWatch
cd ScamWatch
pip install -r requirements.txt
```

Python 3.9+. The only dependency is `requests`.

## Run

```bash
python3 scamwatch.py --once                    # a single pass
python3 scamwatch.py --list                    # everything found so far
python3 scamwatch.py --loop                    # leave it running
python3 scamwatch.py --dry-run                 # detect and score, write nothing
python3 scamwatch.py --no-fingerprint --loop   # fully passive, no GETs at all
python3 scamwatch.py --stats                   # what the database knows
python3 scamwatch.py --export-iocs iocs.csv    # shareable indicator sheet
```

You do not have to read the log. Every pass ends with a plain-English summary
of what it found, why, and what to do about it:

```
========================================================================
  RESULTS   1 confirmed   0 needing a look
  881 pages checked in 23 min 2 sec
========================================================================

  1. [CONFIRMED]  supp0rt-assistance.vercel.app
     page says   : Apple-Support assistance
     why flagged : pretends to be "Apple"; tells visitors to install
                   remote-control software
     phone number: +18888422171
     backed up by: urlscan:malicious
     read this   : out/20260901T101500Z_supp0rt-assistance.vercel.app.md
     check it    : https://urlscan.io/search/#page.domain%3A%22...%22
```

Then it tells you the three steps: read the report, look at the page
yourself, and if you agree, send the pre-addressed `.eml`. Nothing is ever
sent for you.

Passes on a cold database can take twenty minutes or more. `--max-seconds 600`
caps one; whatever it does not reach comes back next pass.

**Set `URLSCAN_API_KEY`.** A free account key is enough. Without one, the
archived-evidence fallback is disabled — and since most scam pages are dead
within a day, that fallback is what lets the tool confirm anything at all. It
runs without a key and warns you when it does.

`python3 scamwatch.py --help` lists every flag. Configuration lives in
`scamwatch.json`, written on first run; see
[docs/DESIGN.md](docs/DESIGN.md#configuration) for the keys worth knowing.

## What comes out

Findings land in one of two tiers:

- **`confirmed`** — content gate **and** an independent signal (a urlscan
  verdict, or a phishing-feed listing). Full evidence report plus an addressed
  `.eml` draft.
- **`review`** — content gate only. A short note, no draft.

Plus `scamwatch.csv` (campaign timeline) and `iocs_phones.csv` — every number
seen, when, and on which domains. That last file is the one worth sharing.

`--list` replays past findings from the database, so you never have to go
digging through the output directory to remember what turned up.

## The rules it will not break

1. **It never sends anything.** It writes drafts; a human reads them.
2. **One ordinary GET per candidate**, exactly what a browser sends. Nothing else.
3. **A domain name is never evidence.** Names are scored separately and
   excluded from confirmation entirely.
4. **It never reports on its own opinion alone.** Something independent must
   agree before a report is addressed.

These exist because the dangerous failure here is not a crash — it is a
well-formed report about a legitimate business. During development the tool
nearly filed against a repair shop, a security vendor's blog, TeamViewer's
China operation, and Vanguard. [The measurements are
here](docs/DESIGN.md#precision-as-measured).

## Limitations

- **Recall is barely measured.** Five confirmed scam pages, zero false
  positives across ~1,700 candidates. Enough to show the pipeline works; not
  enough to claim coverage.
- **No JavaScript is executed** — an HTTP GET only. Image-only or fully
  JS-rendered pages are missed.
- **crt.sh is unreliable**, and a *working* crt.sh costs more time than a
  broken one. [Why](docs/DESIGN.md#limitations-stated-honestly).
- **Verify every report before sending it.** The `.eml` is a draft, not a
  verdict.

## Where this is going

This is the first component of a larger anti-fraud project, and deliberately
the narrowest: watch one scam category, prove the detection is honest, get the
reporting right before widening anything.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). The most valuable contribution is a
**false positive report** — if it flags something legitimate, that is the bug
worth having. Second most valuable is your indicator sheet:

```bash
python3 scamwatch.py --export-iocs iocs.csv
```

The tool never syncs or phones home. Correlation happens because people choose
to publish.

## Tests

```bash
python3 -m unittest
```

## Deploying

A hardened systemd unit is in [contrib/scamwatch.service](contrib/scamwatch.service).

## Scope

A defensive observation and abuse-reporting tool. It reads public sources and
fetches public pages. It contains no exploitation capability and should not
grow any.

## License

MIT — see [LICENSE](LICENSE).
