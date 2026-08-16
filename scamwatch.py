#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
scamwatch.py - automated watcher for fake "live support" / screen-sharing
scam landing pages (tech-support scam ecosystem).

Pipeline: CT logs + urlscan -> candidate domains -> fingerprint (optional)
-> RDAP attribution -> structured abuse-report packages (registrar/host/carrier).

Defensive and passive by design: the only traffic sent to a candidate is a
single ordinary HTTP GET of its landing page, exactly as a browser would.
Pass --no-fingerprint to disable even that and run fully passive.

Nothing is ever mailed automatically. Reports are written to disk as drafts
for a human to read, sanity-check and send.

Requires python3.9+ and `requests`.
Optional env vars: URLSCAN_API_KEY (higher rate limits and full search).

Author: CypherNova1337
Tool used by VoidSec
"""

from __future__ import annotations

import argparse
import csv
import datetime as dt
import email.utils
import json
import logging
import os
import re
import socket
import sqlite3
import sys
import time
from dataclasses import dataclass, field
from email.message import EmailMessage
from pathlib import Path
from typing import Dict, Iterator, List, Optional, Sequence, Set, Tuple

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

log = logging.getLogger("scamwatch")

VERSION = "1.0"
AUTHOR = "CypherNova1337"
PROJECT_NOTE = "Tool used by VoidSec"
UA = f"Mozilla/5.0 (Windows NT 10.0; Win64; x64) scamwatch/{VERSION} (+abuse-intel watcher)"

MAX_BODY_BYTES = 2_000_000
# Consecutive crt.sh failures after which the rest of the pass gives up on it.
CT_FAILURE_LIMIT = 5
# Politeness delay between queries to a shared public service.
CT_QUERY_DELAY = 1.0


# --------------------------------------------------------------------------
# configuration
# --------------------------------------------------------------------------
DEFAULT_CONFIG: Dict = {
    # What actually gets sent to crt.sh. Deliberately broad and cheap: crt.sh
    # runs an ILIKE and degrades hard on selective compound patterns - measured
    # side by side, "%defender%" returns thousands of rows while
    # "%windows-defender%" intermittently returns an empty array or 502s. Ask
    # broad, then refine locally against ct_keywords below. Highest-yield terms
    # come first so a mid-pass circuit-breaker trip still gets the good ones.
    "ct_query_terms": [
        "defender", "anydesk", "teamviewer", "support-live", "support-help",
        "livesupport", "livehelp", "live-chat", "tech-support", "helpdesk",
        "remote-support", "virus-alert", "security-alert", "pc-security",
    ],
    # Require a hostname to match one of ct_keywords/brand_shortcodes below
    # before it becomes a candidate. Set false to keep everything a broad term
    # returns (much noisier).
    "ct_require_refine": True,
    # Local refinement only - these are matched against hostnames already
    # returned by a broad query, never sent to crt.sh directly.
    "ct_keywords": [
        "windows-defender", "microsoft-support", "windows-support",
        "live-support", "live-chat", "tech-support", "pc-security",
        "pc-alert", "security-alert", "system-alert", "virus-alert",
        "anydesk", "teamviewer", "support-help", "support-online",
        "microsoft-alert", "windows-alert", "defender-alert",
        "livehelp", "remote-support", "support-live", "help-desk",
        "billing-support", "refund-support",
    ],
    "brand_shortcodes": [
        "anz-", "nab-", "westpac-", "lloyds-", "santander-", "scotiabank-",
        "kiwibank-", "revolut-", "-anz", "-nab", "-westpac",
    ],
    "urlscan_queries": [
        ["killer_cluster", 'filename:"config.js" AND page.url:"supabase.co"'],
        ["killer_anz", 'page.url:"/anz/" AND page.url:"index.html"'],
        ["live_support", 'page.title:"live support" AND (page.url:"anydesk" OR page.url:"teamviewer")'],
        ["netlify_fake", 'page.domain:"netlify.app" AND page.url:"support"'],
        ["pages_dev_fake", 'page.domain:"pages.dev" AND page.url:"support"'],
        ["vercel_fake", 'page.domain:"vercel.app" AND page.url:"support"'],
        ["remote_tool", 'page.url:"anydesk" OR page.url:"teamviewer" OR page.url:"screenconnect"'],
    ],
    # Keyless public feeds of live phishing/scam URLs. These keep the watcher
    # productive when crt.sh is overloaded, which it frequently is.
    "feed_urls": [
        ["openphish", "https://openphish.com/feed.txt"],
        ["phishing_database",
         "https://raw.githubusercontent.com/mitchellkrogza/Phishing.Database/"
         "master/phishing-domains-ACTIVE.txt"],
    ],
    "feed_max_bytes": 8_000_000,
    # Minimum seconds between re-downloads of a feed; they are large files
    # served for free and change slowly.
    "feed_min_interval": 3600,
    "suspicious_tlds": [
        "sbs", "click", "cfd", "cyou", "xyz", "tk", "ga", "gq", "cf", "ml",
        "top", "club", "space", "online", "site", "icu", "mom", "lol", "rest",
        "quest", "shop", "live",
    ],
    "free_hosts": [
        "netlify.app", "pages.dev", "000webhostapp.com", "github.io",
        "vercel.app", "onrender.com", "glitch.me", "web.app", "firebaseapp.com",
        "workers.dev", "repl.co", "surge.sh", "weeblysite.com",
    ],
    "registrar_abuse": {
        "namecheap": "abuse@namecheap.com",
        "cloudflare": "abuse@cloudflare.com",
        "godaddy": "abuse@godaddy.com",
        "porkbun": "abuse@porkbun.com",
        "namesilo": "abuse@namesilo.com",
        "google": "registrar-abuse@google.com",
        "squarespace": "abuse@squarespace.com",
        "hostinger": "abuse@hostinger.com",
        "ionos": "abuse@ionos.com",
        "gandi": "abuse@gandi.net",
        "tucows": "abuse@tucows.com",
        "enom": "abuse@enom.com",
        "dynadot": "abuse@dynadot.com",
        "namebright": "abuse@namebright.com",
        "openprovider": "abuse@openprovider.com",
        "nicenic": "abuse@nicenic.net",
        "west263": "abuse@west263.com",
    },
    "host_abuse": {
        "netlify": "abuse@netlify.com",
        "cloudflare": "abuse@cloudflare.com",
        "github": "abuse@github.com",
        "hostinger": "abuse@hostinger.com",
        "vercel": "abuse@vercel.com",
        "digitalocean": "abuse@digitalocean.com",
        "amazon": "abuse@amazonaws.com",
        "google": "network-abuse@google.com",
        "microsoft": "abuse@microsoft.com",
        "ovh": "abuse@ovh.net",
        "hetzner": "abuse@hetzner.com",
        "linode": "abuse@linode.com",
        "akamai": "abuse@akamai.com",
        "fastly": "abuse@fastly.com",
        "namecheap": "abuse@namecheap.com",
        "contabo": "abuse@contabo.de",
    },
    # Registrable domains that must never be reported, no matter what a
    # keyword search turns up. Extend this freely; false positives here are
    # far more damaging than missed detections.
    "allowlist": [
        "microsoft.com", "windows.com", "windowsupdate.com", "live.com",
        "msn.com", "office.com", "office365.com", "microsoftonline.com",
        "azure.com", "bing.com", "skype.com", "xbox.com",
        "anydesk.com", "teamviewer.com", "connectwise.com", "screenconnect.com",
        "logmein.com", "gotoassist.com", "splashtop.com", "rustdesk.com",
        "norton.com", "nortonlifelock.com", "mcafee.com", "avast.com",
        "avg.com", "malwarebytes.com", "bitdefender.com", "kaspersky.com",
        "eset.com", "trendmicro.com", "sophos.com", "crowdstrike.com",
        "google.com", "apple.com", "amazon.com", "cloudflare.com",
        "mozilla.org", "adobe.com", "paypal.com", "ebay.com",
        "anz.com", "anz.com.au", "anz.co.nz", "nab.com.au", "westpac.com.au",
        "commbank.com.au", "lloydsbank.com", "lloyds.com", "santander.co.uk",
        "santander.com", "scotiabank.com", "kiwibank.co.nz", "revolut.com",
        "metrobankonline.co.uk", "bankofscotland.co.uk", "halifax.co.uk",
        "letsencrypt.org", "digicert.com", "sectigo.com", "identrust.com",
        "urlscan.io", "virustotal.com", "abuse.ch", "shodan.io",
    ],
    # Brand labels that identify a vendor's own site on ANY TLD, e.g.
    # teamviewer.cn as well as teamviewer.com. Matched against the registrable
    # label exactly, so lookalikes like "anydesk--app.online" are unaffected.
    # Deliberately limited to software vendors, which run many ccTLDs; banks
    # are listed as exact domains in `allowlist` instead.
    "vendor_labels": [
        "microsoft", "windows", "windowsupdate", "office", "office365",
        "microsoftonline", "azure", "skype", "xbox", "msn",
        "anydesk", "teamviewer", "connectwise", "screenconnect", "logmein",
        "gotoassist", "splashtop", "rustdesk", "ultraviewer", "supremo",
        "norton", "nortonlifelock", "mcafee", "avast", "avg", "malwarebytes",
        "bitdefender", "kaspersky", "eset", "trendmicro", "sophos",
        "crowdstrike", "webroot", "avira",
        "google", "apple", "amazon", "cloudflare", "mozilla", "adobe",
        "paypal", "ebay", "netflix", "dropbox", "zoom",
        "letsencrypt", "digicert", "sectigo", "urlscan", "virustotal",
    ],
    # Reporter identity stamped into the .eml drafts. Set this before sending.
    "reporter_from": "",
    "reporter_org": "",
    # Score a domain must reach before a report package is written.
    "confirm_threshold": 6,
    # Score a domain must reach to be kept as a noteworthy candidate.
    "threshold": 4,
}

# Substrings that, when present in page text, count toward the score.
# Short/ambiguous tokens are matched on word boundaries (see compile_markers).
CONTENT_MARKERS: List[Tuple[str, int]] = [
    ("anydesk", 3), ("teamviewer", 3), ("screenconnect", 3), ("connectwise", 3),
    ("ultraviewer", 3), ("rustdesk", 2), ("logmein", 2), ("supremo", 2),
    ("supabase_url", 4), ("access_key", 3), ("entry_file", 3),
    ("live support", 2), ("chat assistance", 2), ("remote session", 3),
    ("download anydesk", 4), ("install anydesk", 4), ("install teamviewer", 4),
    ("windows defender", 2), ("microsoft support", 3), ("security alert", 2),
    ("your computer is infected", 4), ("your device is infected", 4),
    ("your pc is infected", 4), ("call immediately", 3),
    ("do not restart", 3), ("do not shut down", 3), ("do not turn off", 3),
    ("do not close this window", 3), ("call the number", 2),
    ("toll-free", 1), ("toll free", 1), ("helpline", 2),
    ("norton", 2), ("mcafee", 2), ("refund", 1), ("subscription renewal", 2),
    ("billing department", 2), ("unauthorized charge", 3),
    ("virus detected", 4), ("threat detected", 4), ("trojan detected", 4),
    ("spyware detected", 4), ("porn", 2),
    ("enter the code", 2), ("remote control", 2), ("share your screen", 3),
    ("session id", 2), ("access code", 2), ("your password", 2),
    ("certified technician", 3), ("microsoft certified", 3),
    ("error code", 1), ("firewall breach", 3), ("ip address has been", 3),
]

# Bank / brand names whose presence on a non-allowlisted domain is a strong
# impersonation signal. Matched with word boundaries only.
BRAND_MARKERS: List[str] = [
    "anz", "nab", "westpac", "commbank", "lloyds", "santander", "scotiabank",
    "kiwibank", "revolut", "metro bank", "bank of scotland", "halifax",
    "barclays", "natwest", "hsbc", "monzo", "starling",
]

DOMAIN_KEYWORDS: List[str] = [
    "support", "tech", "window", "defender", "alert", "security", "help",
    "fix", "anydesk", "teamviewer", "live", "virus", "protect", "billing",
    "refund", "helpdesk", "secure", "care", "assist",
]

# Second-level public suffixes needed to derive a registrable domain without
# pulling in a full public-suffix list.
MULTI_PART_SUFFIXES: Set[str] = {
    "co.uk", "org.uk", "me.uk", "ltd.uk", "plc.uk", "net.uk", "sch.uk",
    "ac.uk", "gov.uk", "nhs.uk", "police.uk", "mod.uk",
    "com.au", "net.au", "org.au", "edu.au", "gov.au", "asn.au", "id.au",
    "co.nz", "net.nz", "org.nz", "govt.nz", "ac.nz", "school.nz",
    "co.za", "org.za", "net.za", "gov.za", "ac.za",
    "co.in", "net.in", "org.in", "gov.in", "ac.in", "edu.in", "res.in",
    "com.br", "net.br", "org.br", "gov.br", "com.mx", "com.ar", "com.co",
    "co.jp", "or.jp", "ne.jp", "ac.jp", "go.jp", "com.cn", "net.cn",
    "org.cn", "gov.cn", "edu.cn", "com.hk", "com.sg", "com.my", "com.ph",
    "com.tr", "com.ua", "com.pl", "com.tw", "co.kr", "or.kr", "go.kr",
    "co.il", "org.il", "gov.il", "com.eg", "com.sa", "com.pk", "com.bd",
    "co.id", "or.id", "go.id", "com.vn", "com.ng", "co.ke",
    # free-host suffixes: treat the customer label as the registrable unit
    "netlify.app", "pages.dev", "github.io", "vercel.app", "workers.dev",
    "onrender.com", "glitch.me", "web.app", "firebaseapp.com", "repl.co",
    "000webhostapp.com", "surge.sh", "weeblysite.com",
}

# Government / academic / emergency-service suffixes are never reported.
PROTECTED_SUFFIXES: Tuple[str, ...] = (
    ".gov", ".mil", ".edu", ".int",
    ".gov.uk", ".gov.au", ".govt.nz", ".gov.in", ".gov.za", ".gov.br",
    ".ac.uk", ".edu.au", ".ac.nz", ".ac.in", ".edu.cn", ".edu.in",
    ".police.uk", ".nhs.uk", ".mod.uk", ".parliament.uk",
)

# Country codes used to canonicalise numbers into E.164. Longest match wins.
CC_PREFIXES: Tuple[str, ...] = (
    "1", "7", "20", "27", "30", "31", "33", "34", "36", "39", "40", "44",
    "45", "46", "47", "48", "49", "51", "52", "54", "55", "56", "57", "58",
    "60", "61", "62", "63", "64", "65", "66", "81", "82", "84", "86", "90",
    "91", "92", "93", "94", "95", "98", "212", "213", "234", "254", "255",
    "256", "351", "352", "353", "358", "359", "370", "371", "372", "380",
    "420", "421", "852", "853", "855", "856", "880", "886", "960", "961",
    "962", "963", "964", "965", "966", "968", "970", "971", "972", "973",
    "974", "975", "976", "977", "992", "993", "994", "995", "998",
)
CC_SORTED: Tuple[str, ...] = tuple(sorted(CC_PREFIXES, key=len, reverse=True))
RE_NANP = re.compile(r"[2-9]\d{2}[2-9]\d{6}")

RE_TITLE = re.compile(r"<title[^>]*>(.*?)</title>", re.I | re.S)
RE_SCRIPT_STYLE = re.compile(r"<(script|style)\b[^>]*>.*?</\1>", re.I | re.S)
RE_TAG = re.compile(r"<[^>]+>")
RE_TEL_HREF = re.compile(r"""href\s*=\s*["']tel:([^"']{5,32})["']""", re.I)
RE_WS = re.compile(r"\s+")

RE_PHONE_TOLLFREE = re.compile(
    r"(?<![\d/-])(?:\+?1[\s.\-]?)?\(?(?:800|833|844|855|866|877|888)\)?[\s.\-]?\d{3}[\s.\-]?\d{4}(?![\d/-])")
RE_PHONE_US = re.compile(
    r"(?<![\d/-])(?:\+?1[\s.\-]?)?\(?[2-9]\d{2}\)?[\s.\-]?[2-9]\d{2}[\s.\-]?\d{4}(?![\d/-])")
RE_PHONE_UK = re.compile(
    r"(?<![\d/-])(?:\+?44[\s.\-]?|0)(?:800|808|300|330|203|207|208)[\s.\-]?\d{3}[\s.\-]?\d{3,4}(?![\d/-])")
RE_PHONE_AU = re.compile(
    r"(?<![\d/-])(?:\+?61[\s.\-]?|0)(?:1800|1300|2|3|7|8)[\s.\-]?\d{3,4}[\s.\-]?\d{3,4}(?![\d/-])")
# One maximal phone-like run, extracted before any national plan is applied.
RE_PHONE_RUN = re.compile(r"(?<!\w)(\+?\d[\d\s().\-]{6,20}\d)(?!\w)")

# A generic-pattern hit only counts if a calling cue sits near it.
PHONE_CONTEXT = re.compile(
    r"(call|phone|tel|toll|dial|helpline|hotline|support|contact|assist)", re.I)
PHONE_CONTEXT_WINDOW = 60


def compile_markers() -> List[Tuple[str, int, re.Pattern]]:
    """Precompile content markers. Short tokens get word-boundary anchors."""
    out = []
    for text, weight in CONTENT_MARKERS:
        if len(text) <= 8 and " " not in text:
            pat = re.compile(r"(?<![a-z0-9])" + re.escape(text) + r"(?![a-z0-9])")
        else:
            pat = re.compile(re.escape(text))
        out.append((text, weight, pat))
    return out


COMPILED_MARKERS = compile_markers()
COMPILED_BRANDS = [(b, re.compile(r"(?<![a-z0-9])" + re.escape(b) + r"(?![a-z0-9])"))
                   for b in BRAND_MARKERS]


def load_config(path: Path) -> Dict:
    """Load config, merging over defaults so upgrades add keys automatically."""
    cfg = json.loads(json.dumps(DEFAULT_CONFIG))  # deep copy
    if not path.exists():
        path.write_text(json.dumps(cfg, indent=2) + "\n")
        log.info("wrote default config to %s - edit it and rerun", path)
        return cfg
    try:
        user_cfg = json.loads(path.read_text())
    except (json.JSONDecodeError, OSError) as exc:
        log.error("could not read config %s: %s - using defaults", path, exc)
        return cfg
    for key, value in user_cfg.items():
        if isinstance(value, dict) and isinstance(cfg.get(key), dict):
            cfg[key].update(value)
        else:
            cfg[key] = value
    return cfg


# --------------------------------------------------------------------------
# domain helpers
# --------------------------------------------------------------------------
def registrable_domain(domain: str) -> str:
    """Best-effort eTLD+1 without a public-suffix dependency."""
    parts = domain.strip(".").lower().split(".")
    if len(parts) <= 2:
        return ".".join(parts)
    for depth in (3, 2):
        if len(parts) > depth and ".".join(parts[-depth:]) in MULTI_PART_SUFFIXES:
            return ".".join(parts[-(depth + 1):])
    return ".".join(parts[-2:])


def is_allowlisted(domain: str, allowlist: Set[str],
                   vendor_labels: Optional[Set[str]] = None) -> bool:
    domain = domain.lower().strip(".")
    if domain.endswith(PROTECTED_SUFFIXES):
        return True
    if domain in allowlist:
        return True
    reg = registrable_domain(domain)
    if reg in allowlist:
        return True

    # Vendors run their brand on many ccTLDs, and an allowlist of exact
    # domains cannot keep up: teamviewer.cn is TeamViewer's real China site,
    # and a genuine TeamViewer page trips enough content markers to clear the
    # confirmation gate on its own. So exempt anything whose registrable label
    # IS the vendor brand, on any TLD.
    #
    # The cost is a miss if someone registers a brand exactly (teamviewer.xyz);
    # the benefit is never filing an abuse report against the vendor's own
    # site. Lookalikes do not use the bare label - "anydesk--app.online" and
    # "anydesk-win.y--a--hoo.com" both survive this check - so the trade is
    # cheap, and it runs the right way round for a tool that mails third
    # parties.
    if vendor_labels:
        label = reg.split(".", 1)[0]
        if label in vendor_labels:
            return True

    # a subdomain of anything allowlisted
    return any(domain.endswith("." + allowed) for allowed in allowlist)


def valid_domain(domain: str) -> bool:
    if not domain or len(domain) > 253 or "." not in domain:
        return False
    if domain.startswith("-") or ".." in domain:
        return False
    return all(
        part and len(part) <= 63 and re.fullmatch(r"[a-z0-9_-]+", part)
        for part in domain.split(".")
    )


def domain_heuristic_score(domain: str, cfg: Dict) -> int:
    """Cheap score from the name alone. Never enough to confirm on its own."""
    score = 0
    tld = domain.rsplit(".", 1)[-1] if "." in domain else ""
    if tld in set(cfg["suspicious_tlds"]):
        score += 1
    if any(domain == host or domain.endswith("." + host)
           for host in cfg["free_hosts"]):
        score += 1
    hits = sum(1 for kw in DOMAIN_KEYWORDS if kw in domain)
    if hits:
        score += min(hits, 2)
    if domain.count("-") >= 3:
        score += 1
    return score


# --------------------------------------------------------------------------
# storage
# --------------------------------------------------------------------------
class Store:
    """SQLite state: what we have seen, and the running phone-number IOC sheet."""

    def __init__(self, path: Path):
        self.con = sqlite3.connect(str(path))
        self.con.row_factory = sqlite3.Row
        self.con.executescript(
            """
            CREATE TABLE IF NOT EXISTS domains (
                domain      TEXT PRIMARY KEY,
                first_seen  TEXT NOT NULL,
                last_seen   TEXT NOT NULL,
                source      TEXT NOT NULL DEFAULT '',
                status      TEXT NOT NULL DEFAULT 'candidate',
                score       INTEGER NOT NULL DEFAULT 0,
                phones      TEXT NOT NULL DEFAULT '',
                notes       TEXT NOT NULL DEFAULT '',
                reported_at TEXT NOT NULL DEFAULT ''
            );
            CREATE TABLE IF NOT EXISTS phones (
                phone      TEXT PRIMARY KEY,
                first_seen TEXT NOT NULL,
                last_seen  TEXT NOT NULL,
                domains    TEXT NOT NULL DEFAULT '',
                hits       INTEGER NOT NULL DEFAULT 0
            );
            CREATE TABLE IF NOT EXISTS meta (
                key   TEXT PRIMARY KEY,
                value TEXT NOT NULL DEFAULT ''
            );
            CREATE INDEX IF NOT EXISTS idx_domains_status ON domains(status);
            """
        )
        self.con.commit()

    @staticmethod
    def _now() -> str:
        return dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")

    def get_meta(self, key: str, default: str = "") -> str:
        row = self.con.execute(
            "SELECT value FROM meta WHERE key=?", (key,)).fetchone()
        return row["value"] if row else default

    def set_meta(self, key: str, value: str) -> None:
        self.con.execute(
            "INSERT INTO meta VALUES (?,?) "
            "ON CONFLICT(key) DO UPDATE SET value=excluded.value", (key, value))
        self.con.commit()

    def seen(self, domain: str) -> bool:
        return self.con.execute(
            "SELECT 1 FROM domains WHERE domain=?", (domain,)).fetchone() is not None

    def upsert(self, domain: str, source: str, status: str = "candidate",
               score: int = 0, phones: str = "", notes: str = "") -> None:
        """Insert or update, preserving first_seen so the timeline survives."""
        now = self._now()
        self.con.execute(
            """
            INSERT INTO domains (domain, first_seen, last_seen, source,
                                 status, score, phones, notes)
                 VALUES (?,?,?,?,?,?,?,?)
            ON CONFLICT(domain) DO UPDATE SET
                last_seen = excluded.last_seen,
                source    = excluded.source,
                status    = excluded.status,
                score     = excluded.score,
                phones    = excluded.phones,
                notes     = excluded.notes
            """,
            (domain, now, now, source, status, score, phones, notes),
        )
        self.con.commit()

    def mark_reported(self, domain: str) -> None:
        self.con.execute(
            "UPDATE domains SET status='confirmed', reported_at=? WHERE domain=?",
            (self._now(), domain))
        self.con.commit()

    def record_phones(self, phones: Sequence[str], domain: str) -> None:
        now = self._now()
        for phone in phones:
            row = self.con.execute(
                "SELECT domains FROM phones WHERE phone=?", (phone,)).fetchone()
            if row is None:
                self.con.execute(
                    "INSERT INTO phones VALUES (?,?,?,?,1)",
                    (phone, now, now, domain))
            else:
                known = [d for d in row["domains"].split(",") if d]
                if domain not in known:
                    known.append(domain)
                self.con.execute(
                    "UPDATE phones SET last_seen=?, domains=?, hits=hits+1 "
                    "WHERE phone=?", (now, ",".join(known), phone))
        self.con.commit()

    def all_phones(self) -> List[sqlite3.Row]:
        return self.con.execute(
            "SELECT * FROM phones ORDER BY hits DESC, last_seen DESC").fetchall()

    def stats(self) -> Dict[str, int]:
        row = self.con.execute(
            "SELECT COUNT(*) AS total, "
            "SUM(status='confirmed') AS confirmed FROM domains").fetchone()
        phones = self.con.execute("SELECT COUNT(*) AS n FROM phones").fetchone()
        return {"domains": row["total"] or 0,
                "confirmed": row["confirmed"] or 0,
                "phones": phones["n"] or 0}

    def close(self) -> None:
        self.con.close()


# --------------------------------------------------------------------------
# http
# --------------------------------------------------------------------------
def make_api_session() -> requests.Session:
    """Session for the intel APIs: retries on transient errors and 429s."""
    sess = requests.Session()
    sess.headers["User-Agent"] = UA
    # Kept deliberately short: this runs in a loop with a 300s default
    # interval, and a long backoff across dozens of keywords would stall a
    # pass past its own schedule when a source is down.
    retry = Retry(total=3, backoff_factor=1,
                  status_forcelist=(429, 500, 502, 503, 504),
                  allowed_methods=frozenset({"GET"}),
                  raise_on_status=False)
    adapter = HTTPAdapter(max_retries=retry, pool_maxsize=8)
    sess.mount("https://", adapter)
    sess.mount("http://", adapter)
    return sess


def make_probe_session() -> requests.Session:
    """Session for touching candidates: one shot, no retries, no cookies kept."""
    sess = requests.Session()
    sess.headers.update({
        "User-Agent": UA,
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9",
    })
    sess.max_redirects = 5
    return sess


# --------------------------------------------------------------------------
# sources
# --------------------------------------------------------------------------
@dataclass
class SourceHealth:
    """
    Per-source outcome for one pass.

    This exists because the dangerous failure mode of a watcher is not an
    exception - it is a source that quietly returns nothing while the operator
    assumes it is still watching. Every pass reports these explicitly.
    """
    name: str
    queries: int = 0
    failures: int = 0
    yielded: int = 0
    cached: int = 0
    skipped: bool = False
    note: str = ""

    @property
    def ok(self) -> bool:
        return not self.skipped and self.queries > 0 and self.failures < self.queries

    def summary(self) -> str:
        if self.skipped:
            return f"{self.name}=skipped"
        if self.queries == 0:
            return (f"{self.name}=cached({self.cached})" if self.cached
                    else f"{self.name}=NO-QUERIES")
        if self.failures >= self.queries:
            return f"{self.name}=FAILED({self.failures}/{self.queries})"
        state = "ok" if self.yielded else "ok-but-empty"
        detail = f"{self.name}={state}({self.yielded}"
        if self.cached:
            detail += f", {self.cached} cached"
        if self.failures:
            detail += f", {self.failures}/{self.queries} queries failed"
        return detail + ")"


def ct_candidates(sess: requests.Session, query_terms: Sequence[str],
                  refine_keywords: Sequence[str], limit: int,
                  health: SourceHealth, require_refine: bool = True,
                  timeout: int = 60) -> Iterator[Tuple[str, str]]:
    """
    Yield (domain, source_label) for freshly issued certs matching keywords.

    Queries are broad by design and refined locally. crt.sh answers a cheap
    "%defender%" with thousands of rows but intermittently gives an empty
    array or a 502 for "%windows-defender%", so asking narrowly loses
    coverage in a way that is silent and easy to mistake for "no results".
    """
    emitted: Set[str] = set()
    consecutive_failures = 0
    empty_keywords: List[str] = []
    for index, keyword in enumerate(query_terms):
        # crt.sh outages are all-or-nothing. Once it is clearly down, stop
        # hammering it: grinding through the whole keyword list at several
        # seconds per failure would push a pass past its own loop interval.
        if consecutive_failures >= CT_FAILURE_LIMIT:
            health.note = f"gave up after {consecutive_failures} consecutive failures"
            log.warning("crt.sh appears to be down - skipping remaining %d keywords",
                        len(query_terms) - index)
            break
        health.queries += 1
        try:
            # crt.sh does an ILIKE on the identity, so the % wildcards must
            # survive to the server. Note it 502/503s often under load; the
            # session adapter retries those before we give up on the keyword.
            resp = sess.get("https://crt.sh/",
                            params={"q": f"%{keyword}%", "output": "json"},
                            timeout=timeout)
            resp.raise_for_status()
            rows = resp.json()
        except (requests.RequestException, ValueError) as exc:
            health.failures += 1
            consecutive_failures += 1
            log.warning("crt.sh query failed for %r: %s", keyword, exc)
            time.sleep(3)
            continue
        if not isinstance(rows, list):
            health.failures += 1
            consecutive_failures += 1
            continue
        consecutive_failures = 0

        # newest certificates first, so --limit keeps the fresh end
        rows.sort(key=lambda r: str(r.get("entry_timestamp") or ""), reverse=True)

        taken = 0
        for row in rows:
            if taken >= limit:
                break
            names = (row.get("name_value") or "").splitlines()
            for name in names:
                domain = name.strip().strip(".").lower().lstrip("*.")
                if not domain or domain in emitted or not valid_domain(domain):
                    continue
                # crt.sh matches organisation fields too; require the term
                # to actually be in the hostname
                if keyword not in domain:
                    continue
                # A broad term is a cheap way to ask crt.sh a question it can
                # answer, not a detection in itself - "%defender%" returns Land
                # Rover dealerships alongside fake AV pages. Refinement is what
                # makes the result specific, so by default it gates rather than
                # merely labels. Note `limit` counts domains kept, not rows
                # scanned, so precision here does not cost recall.
                refined = next((k for k in refine_keywords if k in domain), "")
                if require_refine and not refined:
                    continue
                emitted.add(domain)
                taken += 1
                health.yielded += 1
                yield domain, f"ct:{keyword}+{refined}" if refined else f"ct:{keyword}"
        if not rows:
            # crt.sh answers some patterns with an empty array rather than an
            # error. Surface it: an operator tuning keywords needs to know
            # which ones are returning nothing at all.
            empty_keywords.append(keyword)
        log.debug("crt.sh %r -> %d rows, %d taken", keyword, len(rows), taken)
        time.sleep(CT_QUERY_DELAY)  # be polite to crt.sh

    if empty_keywords:
        note = f"{len(empty_keywords)} keywords returned no rows"
        health.note = f"{health.note}; {note}" if health.note else note
        log.info("crt.sh returned nothing for %d/%d keywords: %s",
                 len(empty_keywords), health.queries,
                 ", ".join(empty_keywords[:8])
                 + ("..." if len(empty_keywords) > 8 else ""))


def urlscan_candidates(sess: requests.Session,
                       queries: Sequence[Sequence[str]], api_key: str,
                       health: SourceHealth, limit: int = 100,
                       ) -> Iterator[Tuple[str, str]]:
    """Yield (domain, source_label) from urlscan searches for kit signatures."""
    headers = {"API-Key": api_key} if api_key else {}
    for entry in queries:
        try:
            label, query = entry[0], entry[1]
        except (IndexError, TypeError):
            log.warning("skipping malformed urlscan query entry: %r", entry)
            continue
        health.queries += 1
        try:
            resp = sess.get("https://urlscan.io/api/v1/search/",
                            params={"q": query, "size": max(1, min(limit, 100))},
                            headers=headers, timeout=30)
            if resp.status_code == 429:
                health.failures += 1
                health.note = "rate limited - set URLSCAN_API_KEY"
                log.warning("urlscan rate limited (%s); set URLSCAN_API_KEY", label)
                time.sleep(5)
                continue
            resp.raise_for_status()
            data = resp.json()
        except (requests.RequestException, ValueError) as exc:
            health.failures += 1
            log.warning("urlscan query failed (%s): %s", label, exc)
            continue
        count = 0
        for result in data.get("results", []):
            domain = ((result.get("page") or {}).get("domain") or "").strip().lower()
            if domain and valid_domain(domain):
                count += 1
                health.yielded += 1
                yield domain, "urlscan:" + label
        log.debug("urlscan %s -> %d results", label, count)
        time.sleep(1)


def host_from_feed_line(line: str) -> str:
    """Feed lines are either a bare hostname or a full URL. Return the host."""
    line = line.strip()
    if not line or line.startswith("#"):
        return ""
    if "://" in line:
        try:
            host = requests.utils.urlparse(line).hostname or ""
        except ValueError:
            return ""
    else:
        host = line.split("/", 1)[0]
    host = host.strip().strip(".").lower()
    if ":" in host:                       # strip any :port
        host = host.split(":", 1)[0]
    return host if valid_domain(host) else ""


def build_feed_matchers(cfg: Dict) -> Set[str]:
    """Keyword set used to pull tech-support scams out of a general feed."""
    matchers: Set[str] = set()
    for keyword in list(cfg["ct_keywords"]) + list(cfg["brand_shortcodes"]):
        keyword = keyword.strip("-").lower()
        if len(keyword) >= 4:
            matchers.add(keyword)
            matchers.add(keyword.replace("-", ""))
    matchers.update({"anydesk", "teamviewer", "screenconnect", "helpdesk",
                     "techsupport", "windowsdefender", "livesupport"})
    return matchers


def feed_candidates(sess: requests.Session, cfg: Dict, health: SourceHealth,
                    store: "Store") -> Iterator[Tuple[str, str]]:
    """
    Yield (domain, source_label) from keyless public phishing feeds.

    General feeds carry every kind of phishing, so hosts are filtered down to
    the tech-support keyword set before they become candidates.

    These are multi-megabyte files served for free. At the default 300s loop
    interval a naive re-download would pull gigabytes a day from them for
    almost no new data, so fetches are rate-limited locally and revalidated
    with ETag / If-Modified-Since.
    """
    matchers = build_feed_matchers(cfg)
    cap = int(cfg.get("feed_max_bytes", 8_000_000))
    min_interval = int(cfg.get("feed_min_interval", 3600))
    emitted: Set[str] = set()
    now = time.time()

    for entry in cfg.get("feed_urls", []):
        try:
            label, url = entry[0], entry[1]
        except (IndexError, TypeError):
            log.warning("skipping malformed feed entry: %r", entry)
            continue

        last_fetch = float(store.get_meta(f"feed:{label}:fetched", "0") or 0)
        if now - last_fetch < min_interval:
            health.cached += 1
            log.debug("feed %s still fresh (%.0fs old), skipping",
                      label, now - last_fetch)
            continue

        health.queries += 1
        headers = {}
        etag = store.get_meta(f"feed:{label}:etag", "")
        modified = store.get_meta(f"feed:{label}:modified", "")
        if etag:
            headers["If-None-Match"] = etag
        if modified:
            headers["If-Modified-Since"] = modified
        try:
            with sess.get(url, timeout=60, stream=True, headers=headers) as resp:
                if resp.status_code == 304:
                    health.cached += 1
                    store.set_meta(f"feed:{label}:fetched", str(now))
                    log.debug("feed %s unchanged (304)", label)
                    continue
                resp.raise_for_status()
                text = read_body(resp, cap)
                store.set_meta(f"feed:{label}:fetched", str(now))
                if resp.headers.get("ETag"):
                    store.set_meta(f"feed:{label}:etag", resp.headers["ETag"])
                if resp.headers.get("Last-Modified"):
                    store.set_meta(f"feed:{label}:modified",
                                   resp.headers["Last-Modified"])
        except (requests.RequestException, ValueError) as exc:
            health.failures += 1
            log.warning("feed %s failed: %s", label, exc)
            continue

        matched = 0
        for line in text.splitlines():
            host = host_from_feed_line(line)
            if not host or host in emitted:
                continue
            if not any(m in host for m in matchers):
                continue
            emitted.add(host)
            matched += 1
            health.yielded += 1
            yield host, "feed:" + label
        log.debug("feed %s -> %d matching hosts", label, matched)
        time.sleep(1)


# --------------------------------------------------------------------------
# fingerprint
# --------------------------------------------------------------------------
@dataclass
class Fingerprint:
    """
    Scores are kept apart on purpose.

    `heuristic_score` comes from the domain name, which is a ranking hint and
    nothing more - a name cannot prove what a page does. `content_score` comes
    only from what the server actually served. Confirmation reads the content
    score alone, so a suspicious-looking name can never push a page over the
    reporting line by itself.
    """
    domain: str
    heuristic_score: int = 0
    content_score: int = 0
    markers: List[str] = field(default_factory=list)
    phones: List[str] = field(default_factory=list)
    brands: List[str] = field(default_factory=list)
    ip: str = ""
    title: str = ""
    final_url: str = ""
    http_status: int = 0
    fetched: bool = False
    error: str = ""

    @property
    def score(self) -> int:
        return self.heuristic_score + self.content_score

    @property
    def served_ok(self) -> bool:
        """True only when the server actually returned a page (2xx)."""
        return 200 <= self.http_status < 300

    @property
    def has_remote_tool(self) -> bool:
        return any(m in self.markers for m in
                   ("anydesk", "teamviewer", "screenconnect", "connectwise",
                    "ultraviewer", "rustdesk", "logmein", "supremo"))


def strip_html(html: str) -> str:
    text = RE_SCRIPT_STYLE.sub(" ", html)
    text = RE_TAG.sub(" ", text)
    return RE_WS.sub(" ", text)


def normalise_phone(raw: str) -> str:
    """Collapse to +digits / digits. Returns '' if it cannot be a phone number."""
    cleaned = raw.strip()
    plus = cleaned.startswith("+")
    digits = re.sub(r"\D", "", cleaned)
    if not 8 <= len(digits) <= 15:
        return ""
    if len(set(digits)) <= 2:            # 0000000000, 1212121212
        return ""
    if digits.startswith(("19", "20")) and len(digits) <= 8:
        return ""                        # date-like
    if digits in ("1234567890", "0123456789"):
        return ""
    return ("+" if plus else "") + digits


def canonical_phone(raw: str, cc_hint: Optional[str] = None) -> str:
    """
    Canonicalise to E.164 where the country is knowable, so that the same
    call-centre number written three different ways collapses to one IOC.

    `cc_hint` is the country code implied by the regex that matched, which is
    what lets a national-format "0800 123 4567" merge with "+44 800 123 4567".
    """
    norm = normalise_phone(raw)
    if not norm:
        return ""
    plus = norm.startswith("+")
    digits = norm.lstrip("+")

    if plus:
        for cc in CC_SORTED:
            if digits.startswith(cc) and len(digits) - len(cc) >= 6:
                return "+" + cc + digits[len(cc):].lstrip("0")
        return "+" + digits

    # North American numbering plan, with or without the trunk 1
    if len(digits) == 11 and digits.startswith("1"):
        return "+1" + digits[1:]
    if len(digits) == 10 and RE_NANP.fullmatch(digits):
        return "+1" + digits

    if cc_hint:
        if digits.startswith("0"):
            return "+" + cc_hint + digits.lstrip("0")
        if digits.startswith(cc_hint) and len(digits) - len(cc_hint) >= 6:
            return "+" + digits
    return digits


def classify_run(run: str) -> Tuple[int, Optional[str], bool]:
    """
    Classify one phone-like run of text.

    Returns (tier, cc_hint, needs_context). Lower tier is stronger evidence.
    Anything that does not match a known national plan is only accepted when a
    calling cue sits nearby, which is what keeps prices and order numbers out.
    """
    for pattern, tier, cc_hint in ((RE_PHONE_TOLLFREE, 1, "1"),
                                   (RE_PHONE_UK, 2, "44"),
                                   (RE_PHONE_AU, 2, "61"),
                                   (RE_PHONE_US, 3, "1")):
        if pattern.fullmatch(run):
            return tier, cc_hint, False
    return 4, None, True


def extract_phones(html: str) -> List[str]:
    """
    Pull callable numbers out of a page, strongest evidence first.

    Candidate runs are extracted once and then classified, rather than running
    each national-plan pattern over the whole document. That matters: a naive
    pass lets the toll-free pattern match the "800 123 4567" tail inside
    "+44 800 123 4567" and emit a phantom second number for the same line.
    """
    tiered: List[Tuple[int, int, str]] = []   # (tier, position, canonical)
    seen: Set[str] = set()

    def add(tier: int, position: int, raw: str,
            cc_hint: Optional[str] = None) -> None:
        canon = canonical_phone(raw, cc_hint)
        if canon and canon not in seen:
            seen.add(canon)
            tiered.append((tier, position, canon))

    # tel: links are unambiguous - always the best evidence available
    for match in RE_TEL_HREF.finditer(html):
        add(0, match.start(), match.group(1))

    text = strip_html(html)
    for match in RE_PHONE_RUN.finditer(text):
        run = match.group(1).strip(" .-")
        tier, cc_hint, needs_context = classify_run(run)
        if needs_context:
            start = max(0, match.start() - PHONE_CONTEXT_WINDOW)
            window = text[start:match.end() + PHONE_CONTEXT_WINDOW]
            if not PHONE_CONTEXT.search(window):
                continue
        add(tier, match.start(), run, cc_hint)

    tiered.sort(key=lambda item: (item[0], item[1]))
    return [canon for _, _, canon in tiered][:10]


def resolve_ip(host: str) -> str:
    try:
        return socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)[0][4][0]
    except (socket.gaierror, socket.herror, OSError, IndexError):
        return ""


def read_body(resp: requests.Response, cap: int = MAX_BODY_BYTES) -> str:
    """Read at most `cap` bytes and decode. Avoids swallowing huge payloads."""
    chunks: List[bytes] = []
    total = 0
    for chunk in resp.iter_content(65536):
        if not chunk:
            continue
        chunks.append(chunk)
        total += len(chunk)
        if total >= cap:
            break
    raw = b"".join(chunks)[:cap]
    encoding = resp.encoding or resp.apparent_encoding or "utf-8"
    try:
        return raw.decode(encoding, errors="replace")
    except (LookupError, TypeError):
        return raw.decode("utf-8", errors="replace")


def fingerprint(sess: requests.Session, domain: str, cfg: Dict,
                timeout: int = 12) -> Fingerprint:
    """One ordinary GET of the landing page, then score what came back."""
    fp = Fingerprint(domain=domain,
                     heuristic_score=domain_heuristic_score(domain, cfg))
    errors: List[str] = []

    for scheme in ("https", "http"):
        try:
            with sess.get(f"{scheme}://{domain}/", timeout=timeout,
                          allow_redirects=True, stream=True) as resp:
                fp.http_status = resp.status_code
                fp.final_url = resp.url
                html = read_body(resp)
        except requests.RequestException as exc:
            errors.append(f"{scheme}: {exc.__class__.__name__}")
            continue

        fp.fetched = True
        lowered = html.lower()

        match = RE_TITLE.search(html)
        if match:
            fp.title = RE_WS.sub(" ", RE_TAG.sub("", match.group(1))).strip()[:200]

        for text, weight, pattern in COMPILED_MARKERS:
            if pattern.search(lowered):
                fp.markers.append(text)
                fp.content_score += weight

        for brand, pattern in COMPILED_BRANDS:
            if pattern.search(lowered):
                fp.brands.append(brand)
                fp.content_score += 2

        fp.phones = extract_phones(html)
        if fp.phones:
            fp.content_score += 2

        host = domain
        if fp.final_url:
            try:
                host = requests.utils.urlparse(fp.final_url).hostname or domain
            except ValueError:
                host = domain
        fp.ip = resolve_ip(host)
        break

    fp.error = "; ".join(errors)
    return fp


# --------------------------------------------------------------------------
# attribution
# --------------------------------------------------------------------------
def rdap(sess: requests.Session, url: str) -> Dict:
    try:
        resp = sess.get(url, timeout=20)
        if resp.status_code == 200:
            data = resp.json()
            return data if isinstance(data, dict) else {}
    except (requests.RequestException, ValueError) as exc:
        log.debug("rdap %s failed: %s", url, exc)
    return {}


def _vcard_fields(entity: Dict) -> Dict[str, str]:
    """Pull fn/email out of a jCard array, tolerating malformed entries."""
    out: Dict[str, str] = {}
    vcard = entity.get("vcardArray")
    if not isinstance(vcard, list) or len(vcard) < 2:
        return out
    for item in vcard[1]:
        if not isinstance(item, list) or len(item) < 4:
            continue
        key, value = item[0], item[3]
        if isinstance(value, list):
            value = " ".join(str(v) for v in value if v)
        if isinstance(key, str) and isinstance(value, str) and value:
            out.setdefault(key, value)
    return out


def _walk_entities(entities) -> Iterator[Dict]:
    if not isinstance(entities, list):
        return
    for entity in entities:
        if isinstance(entity, dict):
            yield entity
            yield from _walk_entities(entity.get("entities"))


def registrar_from_rdap(data: Dict) -> Tuple[str, str]:
    """Return (registrar_name, abuse_email) from an RDAP domain object."""
    name, abuse_email, fallback_email = "", "", ""
    for entity in _walk_entities(data.get("entities")):
        roles = entity.get("roles") or []
        fields = _vcard_fields(entity)
        if "registrar" in roles and not name:
            name = fields.get("fn", "")
        if "abuse" in roles and fields.get("email"):
            abuse_email = abuse_email or fields["email"]
        elif fields.get("email"):
            fallback_email = fallback_email or fields["email"]
    return name, abuse_email or fallback_email


def org_from_rdap(data: Dict) -> str:
    for key in ("name", "handle"):
        value = data.get(key)
        if isinstance(value, str) and value:
            return value
    for entity in _walk_entities(data.get("entities")):
        fields = _vcard_fields(entity)
        if fields.get("fn"):
            return fields["fn"]
    return ""


def ip_attribution(sess: requests.Session, ip: str) -> Tuple[str, str]:
    """Return (network_org, abuse_email) for an IP via RDAP."""
    if not ip:
        return "", ""
    data = rdap(sess, f"https://rdap.org/ip/{ip}")
    if not data:
        return "", ""
    org = org_from_rdap(data)
    abuse_email = ""
    for entity in _walk_entities(data.get("entities")):
        if "abuse" in (entity.get("roles") or []):
            fields = _vcard_fields(entity)
            if fields.get("email"):
                abuse_email = fields["email"]
                break
    return org, abuse_email


@dataclass
class Attribution:
    registrar: str = ""
    registrar_abuse: str = ""
    host_org: str = ""
    host_abuse: str = ""
    created: str = ""
    nameservers: List[str] = field(default_factory=list)


def attribute(sess: requests.Session, domain: str, fp: Fingerprint,
              cfg: Dict) -> Attribution:
    att = Attribution()
    data = rdap(sess, f"https://rdap.org/domain/{registrable_domain(domain)}")

    att.registrar, att.registrar_abuse = registrar_from_rdap(data)
    if not att.registrar_abuse:
        haystack = att.registrar.lower()
        for key, addr in cfg["registrar_abuse"].items():
            if key in haystack:
                att.registrar_abuse = addr
                break

    for event in data.get("events", []) or []:
        if isinstance(event, dict) and event.get("eventAction") == "registration":
            att.created = str(event.get("eventDate") or "")[:19]
            break

    for ns in data.get("nameservers", []) or []:
        if isinstance(ns, dict) and ns.get("ldhName"):
            att.nameservers.append(str(ns["ldhName"]).lower())

    # free hosts are identifiable from the name alone
    for host, addr in cfg["host_abuse"].items():
        if host in domain:
            att.host_org, att.host_abuse = host, addr
            break

    if not att.host_abuse:
        org, abuse_email = ip_attribution(sess, fp.ip)
        att.host_org = org
        att.host_abuse = abuse_email
        if not att.host_abuse and org:
            lowered = org.lower()
            for host, addr in cfg["host_abuse"].items():
                if host in lowered:
                    att.host_abuse = addr
                    break
    return att


# --------------------------------------------------------------------------
# reports
# --------------------------------------------------------------------------
def _bullets(items: Sequence[str], empty: str = "- none observed") -> str:
    return "\n".join("- " + item for item in items) if items else empty


def build_markdown(domain: str, fp: Fingerprint, att: Attribution,
                   source: str, timestamp: str) -> str:
    quoted = requests.utils.quote(domain)
    return f"""# Tech-support scam landing page - {domain}

| Field | Value |
|---|---|
| Domain | `{domain}` |
| First observed | {timestamp} UTC |
| Detection source | {source} |
| Resolved IP | {fp.ip or 'n/a'} |
| HTTP status | {fp.http_status or 'n/a'} |
| Final URL | {fp.final_url or 'n/a'} |
| Page title | {fp.title or 'n/a'} |
| Evidence score | {fp.content_score} (from served content; confirmation threshold) |
| Name heuristic | {fp.heuristic_score} (ranking hint only, excluded from confirmation) |
| Registered | {att.created or 'unknown'} |

## Summary

The page at `{domain}` presents itself as a technical-support or security
service and directs visitors to install remote-access software and/or call a
telephone number. This is the standard delivery pattern for tech-support
fraud: the caller takes remote control of the victim's machine, displays
fabricated evidence of infection, and extracts payment or bank credentials.

## Matched indicators

{_bullets(fp.markers, '- none (candidate did not serve matching content)')}

## Brands impersonated

{_bullets(fp.brands, '- none detected')}

## Telephone numbers observed

These are the durable indicator. Domains are re-registered within minutes;
call-centre numbers persist for weeks and tie campaigns together.

{_bullets(fp.phones)}

## Attribution

- Registrar: {att.registrar or 'unknown'}
- Registrar abuse contact: {att.registrar_abuse or 'look up manually'}
- Hosting / network: {att.host_org or 'unknown'}
- Hosting abuse contact: {att.host_abuse or 'look up manually'}
- Nameservers: {', '.join(att.nameservers) or 'unknown'}

## Corroboration

- urlscan: https://urlscan.io/search/#page.domain%3A%22{quoted}%22
- VirusTotal: https://www.virustotal.com/gui/domain/{quoted}
- crt.sh: https://crt.sh/?q={quoted}

## Where to send this

| Channel | Destination |
|---|---|
| Registrar abuse | {att.registrar_abuse or 'look up at registrar'} |
| Hosting abuse | {att.host_abuse or 'look up at host'} |
| US - IC3 | https://www.ic3.gov |
| US - FTC | https://reportfraud.ftc.gov |
| UK - Action Fraud | https://www.actionfraud.police.uk |
| India - I4C / 1930 | https://cybercrime.gov.in |
| Australia - Scamwatch | https://www.scamwatch.gov.au |
| Malicious URL feed | https://urlhaus.abuse.ch |

Phone numbers should additionally be reported to the terminating carrier and,
for India-based call centres, batched to I4C. Number takedowns cost the
operation days of rebuild time; domain takedowns cost minutes.

---
scamwatch {VERSION} - {AUTHOR}. {PROJECT_NOTE}.
Automated detection: verify the evidence above before sending this anywhere.
"""


def build_eml(domain: str, fp: Fingerprint, att: Attribution,
              cfg: Dict, report_name: str) -> bytes:
    recipients = [addr for addr in (att.registrar_abuse, att.host_abuse) if addr]
    msg = EmailMessage()
    msg["To"] = ", ".join(recipients) if recipients else "abuse@REPLACE-ME"
    if cfg.get("reporter_from"):
        msg["From"] = cfg["reporter_from"]
    msg["Subject"] = f"[Abuse] Tech-support scam landing page: {domain}"
    msg["Date"] = email.utils.formatdate(localtime=True)
    msg["Message-ID"] = email.utils.make_msgid(domain="scamwatch.invalid")

    signature = cfg.get("reporter_org") or "(sender - complete before sending)"
    msg["X-Report-Generator"] = f"scamwatch/{VERSION}"

    # Only claim what the markers actually support. A report that overstates
    # its evidence is worth less than no report at all, and abuse desks that
    # catch one exaggeration discount everything that follows it.
    if fp.has_remote_tool:
        mechanism = (
            "The page instructs visitors to install remote-access software\n"
            "(AnyDesk / TeamViewer / ConnectWise ScreenConnect) and to hand over a\n"
            "remote session, which is the standard tech-support fraud pattern.")
    elif fp.phones:
        mechanism = (
            "The page presents a fabricated security or billing warning together\n"
            "with a telephone number, which is the standard entry point for\n"
            "tech-support fraud: the call handler then talks the victim into\n"
            "granting remote access or making a payment.")
    else:
        mechanism = (
            "The page presents a fabricated security or billing warning designed\n"
            "to panic visitors into contacting the operator.")
    msg.set_content(f"""Hello,

The domain below is serving an active tech-support scam landing page and is
being used to defraud members of the public. I am reporting it for suspension.

Domain:      {domain}
Final URL:   {fp.final_url or 'n/a'}
IP address:  {fp.ip or 'n/a'}
Registrar:   {att.registrar or 'unknown'}
Registered:  {att.created or 'unknown'}
Observed:    {dt.datetime.now(dt.timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}

Indicators observed on the page:
{_bullets(fp.markers, '- see attached report')}

Brands impersonated:
{_bullets(fp.brands, '- none detected')}

Telephone numbers presented to visitors:
{_bullets(fp.phones)}

{mechanism} Independent
corroboration is available at:

  https://urlscan.io/search/#page.domain%3A%22{requests.utils.quote(domain)}%22

Please suspend the domain and preserve registration, payment and access logs
for law enforcement. I am happy to supply further evidence on request.

Full technical report: {report_name}

Regards,
{signature}
""")
    return msg.as_bytes()


def append_csv(path: Path, row: Sequence[str]) -> None:
    header = ["timestamp", "domain", "source", "content_score",
              "heuristic_score", "ip", "registrar", "registrar_abuse",
              "host_org", "host_abuse", "phones", "brands", "title"]
    exists = path.exists()
    with path.open("a", newline="", encoding="utf-8") as fh:
        writer = csv.writer(fh)
        if not exists:
            writer.writerow(header)
        writer.writerow(row)


def write_ioc_sheet(store: Store, path: Path) -> None:
    """Rewrite the master phone-number IOC sheet from accumulated state."""
    with path.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.writer(fh)
        writer.writerow(["phone", "first_seen", "last_seen", "domains", "hits"])
        for row in store.all_phones():
            writer.writerow([row["phone"], row["first_seen"], row["last_seen"],
                             row["domains"], row["hits"]])


def write_reports(sess: requests.Session, domain: str, fp: Fingerprint,
                  source: str, outdir: Path, cfg: Dict) -> Attribution:
    att = attribute(sess, domain, fp, cfg)
    timestamp = dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    slug = re.sub(r"[^a-z0-9.-]", "_", domain)[:80]

    md_path = outdir / f"{timestamp}_{slug}.md"
    eml_path = outdir / f"{timestamp}_{slug}.eml"

    md_path.write_text(build_markdown(domain, fp, att, source, timestamp),
                       encoding="utf-8")
    eml_path.write_bytes(build_eml(domain, fp, att, cfg, md_path.name))

    append_csv(outdir / "scamwatch.csv", [
        timestamp, domain, source, fp.content_score, fp.heuristic_score,
        fp.ip, att.registrar, att.registrar_abuse, att.host_org, att.host_abuse,
        " ".join(fp.phones), " ".join(fp.brands), fp.title,
    ])
    log.info("report written: %s (+ %s)", md_path.name, eml_path.name)
    return att


# --------------------------------------------------------------------------
# pipeline
# --------------------------------------------------------------------------
def collect_candidates(args, cfg: Dict, store: Store, api: requests.Session,
                       ) -> Tuple[Dict[str, str], List[SourceHealth]]:
    """Gather new candidate domains from every enabled source."""
    allowlist = {d.lower() for d in cfg["allowlist"]}
    vendor_labels = {v.lower() for v in cfg.get("vendor_labels", [])}
    candidates: Dict[str, str] = {}
    skipped_allow = 0

    ct_health = SourceHealth("ct", skipped=args.no_ct)
    urlscan_health = SourceHealth("urlscan", skipped=args.no_urlscan)
    feed_health = SourceHealth("feeds", skipped=args.no_feeds)
    healths = [ct_health, urlscan_health, feed_health]

    def consider(domain: str, source: str) -> None:
        nonlocal skipped_allow
        if domain in candidates:
            return
        if is_allowlisted(domain, allowlist, vendor_labels):
            skipped_allow += 1
            return
        if not args.force and store.seen(domain):
            return
        candidates[domain] = source

    if not args.no_ct:
        query_terms = list(cfg.get("ct_query_terms") or cfg["ct_keywords"])
        refine = list(cfg["ct_keywords"]) + list(cfg["brand_shortcodes"])
        for domain, source in ct_candidates(
                api, query_terms, refine, args.limit, ct_health,
                require_refine=bool(cfg.get("ct_require_refine", True))):
            consider(domain, source)

    if not args.no_urlscan:
        for domain, source in urlscan_candidates(
                api, cfg["urlscan_queries"],
                os.environ.get("URLSCAN_API_KEY", ""),
                urlscan_health, args.limit):
            consider(domain, source)

    if not args.no_feeds:
        for domain, source in feed_candidates(api, cfg, feed_health, store):
            consider(domain, source)

    if skipped_allow:
        log.info("skipped %d allowlisted domains", skipped_allow)
    return candidates, healths


def should_confirm(fp: Fingerprint, cfg: Dict) -> bool:
    """
    Gate on evidence the page actually served, never on the name.

    Three things must hold before anything is reported: the server returned a
    real page (a 403/451 takedown stub proves nothing), that page matched
    content markers, and the evidence clears the bar on its own - the domain
    heuristic is excluded so a name like "windows-defender-alert.sbs" cannot
    top up a single weak marker into a confirmation.
    """
    if not fp.fetched or not fp.served_ok or not fp.markers:
        return False
    if fp.phones and fp.has_remote_tool:
        return True
    if fp.brands and fp.has_remote_tool:
        return True
    return fp.content_score >= cfg["confirm_threshold"]


def run_once(args, cfg: Dict, store: Store, api: requests.Session,
             probe: requests.Session) -> None:
    candidates, healths = collect_candidates(args, cfg, store, api)

    log.info("sources: %s", "  ".join(h.summary() for h in healths))
    active = [h for h in healths if not h.skipped]
    attempted = [h for h in active if h.queries > 0]
    if attempted and all(h.failures >= h.queries for h in attempted):
        log.error("every enabled source failed this pass - the watcher is blind, "
                  "check network access and source availability")
    elif attempted and not any(h.yielded for h in active):
        log.warning("no source returned any domain this pass")

    log.info("new candidates: %d", len(candidates))

    confirmed = 0
    for domain, source in sorted(candidates.items()):
        if args.no_fingerprint:
            store.upsert(domain, source, "candidate",
                         domain_heuristic_score(domain, cfg))
            log.debug("passive candidate: %s (%s)", domain, source)
            continue

        fp = fingerprint(probe, domain, cfg)
        store.upsert(domain, source, "candidate", fp.score,
                     ",".join(fp.phones), ";".join(fp.markers[:12]))

        if should_confirm(fp, cfg):
            confirmed += 1
            store.record_phones(fp.phones, domain)
            if args.dry_run:
                log.info("[dry-run] would report %s (score %d, phones %s)",
                         domain, fp.score, fp.phones or "none")
            else:
                write_reports(api, domain, fp, source, args.out, cfg)
                store.mark_reported(domain)
        else:
            log.debug("below threshold: %s score=%d fetched=%s markers=%s",
                      domain, fp.score, fp.fetched, fp.markers[:5])
        time.sleep(args.delay)

    if not args.dry_run and not args.no_fingerprint:
        write_ioc_sheet(store, args.out / "iocs_phones.csv")

    log.info("pass complete: %d candidates, %d confirmed (reports in %s)",
             len(candidates), confirmed, args.out)


def print_stats(store: Store) -> None:
    stats = store.stats()
    print(f"domains tracked : {stats['domains']}")
    print(f"confirmed       : {stats['confirmed']}")
    print(f"phone IOCs      : {stats['phones']}")
    rows = store.all_phones()[:20]
    if rows:
        print("\ntop phone numbers:")
        for row in rows:
            print(f"  {row['phone']:<18} hits={row['hits']:<4} {row['domains'][:60]}")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="scamwatch",
        description="Watch CT logs and urlscan for fake live-support scam "
                    "pages and package abuse reports.")
    parser.add_argument("--once", action="store_true",
                        help="run a single pass and exit (default)")
    parser.add_argument("--loop", action="store_true",
                        help="run continuously")
    parser.add_argument("--interval", type=int, default=300,
                        help="seconds between passes in loop mode (default 300)")
    parser.add_argument("--no-ct", action="store_true",
                        help="skip crt.sh certificate-transparency monitoring")
    parser.add_argument("--no-urlscan", action="store_true",
                        help="skip urlscan.io monitoring")
    parser.add_argument("--no-feeds", action="store_true",
                        help="skip the public phishing feeds")
    parser.add_argument("--no-fingerprint", action="store_true",
                        help="fully passive: never contact candidates; "
                             "records names only, writes no reports")
    parser.add_argument("--dry-run", action="store_true",
                        help="detect and score, but write no report files")
    parser.add_argument("--force", action="store_true",
                        help="reprocess domains already in the database")
    parser.add_argument("--stats", action="store_true",
                        help="print database summary and exit")
    parser.add_argument("--out", type=Path, default=Path("out"),
                        help="report output directory (default ./out)")
    parser.add_argument("--config", type=Path, default=Path("scamwatch.json"),
                        help="config file (default ./scamwatch.json)")
    parser.add_argument("--db", type=Path, default=Path("scamwatch.db"),
                        help="state database (default ./scamwatch.db)")
    parser.add_argument("--limit", type=int, default=50,
                        help="max results per source query (default 50)")
    parser.add_argument("--delay", type=float, default=0.5,
                        help="seconds between candidate fetches (default 0.5)")
    parser.add_argument("-v", "--verbose", action="store_true")
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)-7s %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S%z")

    args.db.parent.mkdir(parents=True, exist_ok=True)
    store = Store(args.db)

    if args.stats:
        try:
            print_stats(store)
        finally:
            store.close()
        return 0

    args.out.mkdir(parents=True, exist_ok=True)
    cfg = load_config(args.config)

    if args.no_ct and args.no_urlscan and args.no_feeds:
        log.error("all sources disabled - nothing to do")
        store.close()
        return 2
    if args.no_fingerprint:
        log.warning("passive mode: candidates are recorded but not verified, "
                    "and no reports will be written")

    api = make_api_session()
    probe = make_probe_session()

    def one_pass() -> None:
        try:
            run_once(args, cfg, store, api, probe)
        except KeyboardInterrupt:
            raise
        except Exception:
            log.exception("pass failed")

    try:
        if args.loop:
            while True:
                one_pass()
                log.info("sleeping %ds", args.interval)
                time.sleep(args.interval)
        else:
            one_pass()
    except KeyboardInterrupt:
        log.info("interrupted")
        return 130
    finally:
        store.close()
        api.close()
        probe.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
