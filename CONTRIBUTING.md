# Contributing

The most valuable contribution is not code. It is telling us when the tool is
wrong.

## Report a false positive first

This tool generates abuse reports about websites. Its dangerous failure is not
a crash — it is a well-formed, correctly addressed report about somebody's
legitimate business, which looks identical to success in every log line.

Every false positive found so far came from a human reading the output. None
came from a metric. During development the tool nearly filed reports against
a computer repair shop in Oklahoma, a security vendor's blog, TeamViewer's
China operation, and Vanguard.

If it flags something legitimate, **open a false-positive issue.** That is the
highest-value bug report this project can receive.

## Share your indicator sheet

```bash
python3 scamwatch.py --export-iocs iocs.csv
```

The file contains phone numbers, the domains they appeared on, and dates.
Nothing local, nothing sensitive, safe to publish.

Numbers recur across campaigns. One number on two domains in your database and
three more in someone else's is an operation, not a coincidence — and that is
the form a law-enforcement referral can actually use. The tool does not sync
anything and never phones home; correlation happens because people choose to
publish.

## Code

- Python 3.9+, standard library plus `requests`. Keep it one file.
- `python3 -m unittest` before opening a PR. Everything must pass.
- New detection rules need a test pinned to a real observed page, not a
  hypothetical one. Look at the existing regression tests for the shape: each
  names the live case that motivated it.
- Widening detection requires evidence it does not widen false positives.
  Anything that makes the tool report more must show what it does to the
  legitimate pages already in the test suite.

## Things we will not merge

- Anything that contacts a target beyond one ordinary GET
- Anything that sends a report automatically, without a human reading it
- Scraping or exploitation of scam infrastructure
- Detection based on the domain name alone
