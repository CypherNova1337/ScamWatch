#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Tests for scamwatch. Run with:  python3 -m unittest -v

These cover the parts where a mistake has a real cost: the allowlist (a false
positive means mailing an abuse desk about a legitimate business), phone
extraction (the durable IOC), and state handling (the campaign timeline).
"""

import json
import tempfile
import unittest
from pathlib import Path

import scamwatch as sw


class TestRegistrableDomain(unittest.TestCase):
    def test_plain(self):
        self.assertEqual(sw.registrable_domain("example.com"), "example.com")
        self.assertEqual(sw.registrable_domain("a.b.example.com"), "example.com")

    def test_multi_part_suffix(self):
        self.assertEqual(sw.registrable_domain("anz.com.au"), "anz.com.au")
        self.assertEqual(sw.registrable_domain("login.anz.com.au"), "anz.com.au")
        self.assertEqual(sw.registrable_domain("foo.bar.co.uk"), "bar.co.uk")

    def test_free_host_customer_label_is_the_unit(self):
        self.assertEqual(sw.registrable_domain("evil.netlify.app"),
                         "evil.netlify.app")
        self.assertEqual(sw.registrable_domain("a.evil.pages.dev"),
                         "evil.pages.dev")

    def test_short_input(self):
        self.assertEqual(sw.registrable_domain("localhost"), "localhost")


class TestAllowlist(unittest.TestCase):
    def setUp(self):
        self.allow = {d.lower() for d in sw.DEFAULT_CONFIG["allowlist"]}

    def test_legitimate_vendors_are_never_reported(self):
        for domain in ("microsoft.com", "support.microsoft.com",
                       "anydesk.com", "download.anydesk.com",
                       "anz.com.au", "login.anz.com.au", "norton.com"):
            with self.subTest(domain=domain):
                self.assertTrue(sw.is_allowlisted(domain, self.allow))

    def test_government_and_academic_suffixes_protected(self):
        for domain in ("fbi.gov", "ic3.gov", "cyber.gov.au",
                       "actionfraud.police.uk", "mit.edu", "ox.ac.uk"):
            with self.subTest(domain=domain):
                self.assertTrue(sw.is_allowlisted(domain, self.allow))

    def test_lookalikes_are_not_allowlisted(self):
        for domain in ("microsoft-support-live.sbs",
                       "anz-secure-login.click",
                       "anydesk-download.xyz",
                       "notmicrosoft.com"):
            with self.subTest(domain=domain):
                self.assertFalse(sw.is_allowlisted(domain, self.allow))

    def test_suffix_confusion_does_not_grant_a_pass(self):
        # must not match by bare substring
        self.assertFalse(sw.is_allowlisted("evilmicrosoft.com", self.allow))
        self.assertFalse(sw.is_allowlisted("microsoft.com.evil.sbs", self.allow))


class TestVendorLabelAllowlist(unittest.TestCase):
    """
    Regression, observed live: a broad crt.sh term returned teamviewer.cn and
    five of its subdomains. That is TeamViewer's real China operation, and a
    genuine TeamViewer page trips teamviewer + remote control + session id =
    7, over the confirmation threshold. Without this rule the tool would have
    filed an abuse report against the vendor's own site.
    """

    def setUp(self):
        self.allow = {d.lower() for d in sw.DEFAULT_CONFIG["allowlist"]}
        self.vendors = {v.lower() for v in sw.DEFAULT_CONFIG["vendor_labels"]}

    def _check(self, domain):
        return sw.is_allowlisted(domain, self.allow, self.vendors)

    def test_vendor_brand_on_any_tld_is_exempt(self):
        for domain in ("teamviewer.cn", "dl.teamviewer.cn",
                       "rlb.router.teamviewer.cn", "anydesk.de",
                       "microsoft.co.jp", "norton.com.au"):
            with self.subTest(domain=domain):
                self.assertTrue(self._check(domain))

    def test_lookalikes_still_pass_through(self):
        for domain in ("anydesk--app.online", "anydesk--pro.online",
                       "www.anydesk-win.y--a--hoo.com",
                       "anydesk-wake-on-lan--458392.steinengel.de",
                       "windows-defender-security-center--642456696.borsan.de",
                       "live-support-defender.sbs"):
            with self.subTest(domain=domain):
                self.assertFalse(self._check(domain))

    def test_brand_must_be_the_whole_label(self):
        """"anydesk-app.x" is not "anydesk.x" - only an exact label exempts."""
        self.assertFalse(self._check("anydesk-app.online"))
        self.assertFalse(self._check("myteamviewer.net"))
        self.assertFalse(self._check("teamviewer-support.sbs"))

    def test_omitting_vendor_labels_preserves_old_behaviour(self):
        self.assertFalse(sw.is_allowlisted("teamviewer.cn", self.allow))
        self.assertTrue(sw.is_allowlisted("teamviewer.com", self.allow))


class TestValidDomain(unittest.TestCase):
    def test_accepts_normal(self):
        self.assertTrue(sw.valid_domain("live-support.sbs"))
        self.assertTrue(sw.valid_domain("a.b.c.example.co.uk"))

    def test_rejects_junk(self):
        for bad in ("", "nodot", "-lead.com", "a..b.com", "sp ace.com",
                    "x" * 300 + ".com"):
            with self.subTest(bad=bad):
                self.assertFalse(sw.valid_domain(bad))


class TestPhoneNormalisation(unittest.TestCase):
    def test_normalises_formatting(self):
        self.assertEqual(sw.normalise_phone("1 (833) 555-0142"), "18335550142")
        self.assertEqual(sw.normalise_phone("+44 800 123 4567"), "+448001234567")

    def test_rejects_non_phones(self):
        for bad in ("2024", "1234", "0000000000", "1212121212",
                    "12345678901234567890", "19990101"):
            with self.subTest(bad=bad):
                self.assertEqual(sw.normalise_phone(bad), "")


class TestPhoneExtraction(unittest.TestCase):
    def test_tel_href_wins_and_is_first(self):
        html = '<a href="tel:+18885550199">Call now</a> ... 555 other 123 4567'
        phones = sw.extract_phones(html)
        self.assertEqual(phones[0], "+18885550199")

    def test_toll_free_in_body_text(self):
        html = "<p>Call our helpline at 1-833-555-0142 immediately</p>"
        self.assertIn("+18335550142", sw.extract_phones(html))

    def test_generic_number_requires_calling_context(self):
        without = sw.extract_phones("<p>Order +49 30 123456789 shipped</p>")
        withctx = sw.extract_phones("<p>Call support on +49 30 123456789</p>")
        self.assertEqual(without, [])
        self.assertTrue(withctx)

    def test_ignores_script_noise(self):
        html = ('<script>var v="1234567890123";</script>'
                '<p>Call 1-833-555-0142</p>')
        self.assertEqual(sw.extract_phones(html), ["+18335550142"])

    def test_deduplicates_across_formats(self):
        html = ('<a href="tel:18335550142">call</a>'
                '<p>call 1 (833) 555-0142 or 833.555.0142</p>')
        self.assertEqual(sw.extract_phones(html), ["+18335550142"])

    def test_national_and_international_uk_forms_merge(self):
        html = ("<p>Call 0800 123 4567 now, or dial +44 800 123 4567 "
                "from abroad</p>")
        self.assertEqual(sw.extract_phones(html), ["+448001234567"])

    def test_caps_output(self):
        html = "".join(f'<a href="tel:1833555{i:04d}">c</a>' for i in range(40))
        self.assertLessEqual(len(sw.extract_phones(html)), 10)


class TestCanonicalPhone(unittest.TestCase):
    def test_nanp_forms_collapse(self):
        for raw in ("1-833-555-0142", "833.555.0142", "(833) 555-0142",
                    "+1 833 555 0142"):
            with self.subTest(raw=raw):
                self.assertEqual(sw.canonical_phone(raw, "1"), "+18335550142")

    def test_country_code_hint_applied_to_national_format(self):
        self.assertEqual(sw.canonical_phone("0800 123 4567", "44"),
                         "+448001234567")
        self.assertEqual(sw.canonical_phone("+44 800 123 4567"), "+448001234567")

    def test_longest_country_code_wins(self):
        self.assertEqual(sw.canonical_phone("+353 1 234 5678"), "+35312345678")

    def test_unknown_origin_left_alone(self):
        self.assertEqual(sw.canonical_phone("020 7946 0000"), "02079460000")

    def test_junk_rejected(self):
        self.assertEqual(sw.canonical_phone("2024"), "")


class TestMarkerMatching(unittest.TestCase):
    def test_short_brand_tokens_use_word_boundaries(self):
        pattern = dict((b, p) for b, p in sw.COMPILED_BRANDS)["anz"]
        self.assertTrue(pattern.search("welcome to anz internet banking"))
        self.assertFalse(pattern.search("please stop the anzeigen popup"))
        self.assertFalse(pattern.search("bonanza"))

    def test_multiword_markers_match_literally(self):
        marker = dict((t, p) for t, _, p in sw.COMPILED_MARKERS)["share your screen"]
        self.assertTrue(marker.search("please share your screen with us"))


class TestHeuristicScore(unittest.TestCase):
    def setUp(self):
        self.cfg = sw.DEFAULT_CONFIG

    def test_suspicious_name_scores(self):
        score = sw.domain_heuristic_score("live-support-windows-defender.sbs",
                                          self.cfg)
        self.assertGreaterEqual(score, 3)

    def test_boring_name_scores_low(self):
        self.assertEqual(sw.domain_heuristic_score("example.com", self.cfg), 0)


class TestConfirmationGate(unittest.TestCase):
    def setUp(self):
        self.cfg = sw.DEFAULT_CONFIG

    def test_never_confirms_without_a_fetch(self):
        fp = sw.Fingerprint(domain="x.sbs", content_score=99)
        self.assertFalse(sw.should_confirm(fp, self.cfg))

    def test_never_confirms_on_domain_name_alone(self):
        fp = sw.Fingerprint(domain="windows-defender-support.sbs",
                            heuristic_score=99, fetched=True,
                            http_status=200, markers=[])
        self.assertFalse(sw.should_confirm(fp, self.cfg))

    def test_domain_heuristic_cannot_top_up_a_weak_marker(self):
        """
        Regression, observed live: a support-themed page whose only marker was
        "error code" plus a phone number reached a combined score of 6 and was
        reported. The name contributed half of that. Confirmation must read the
        content score alone, so this case now falls well short.
        """
        fp = sw.Fingerprint(domain="direct-tv-customer-support-number.pages.dev",
                            heuristic_score=3, content_score=3, fetched=True,
                            http_status=200, markers=["error code"],
                            phones=["+13329100008"])
        self.assertEqual(fp.score, 6)               # would have passed a raw gate
        self.assertFalse(sw.should_confirm(fp, self.cfg))

    def test_phone_alone_is_not_enough_without_a_remote_tool(self):
        """A support number on a page is not by itself a tech-support scam."""
        fp = sw.Fingerprint(domain="x.sbs", content_score=3, fetched=True,
                            http_status=200, markers=["helpline"],
                            phones=["+18335550142"])
        self.assertFalse(sw.should_confirm(fp, self.cfg))

    def test_takedown_stub_is_not_evidence(self):
        for status in (403, 451, 402, 404, 500):
            with self.subTest(status=status):
                fp = sw.Fingerprint(domain="x.sbs", content_score=20,
                                    fetched=True, http_status=status,
                                    markers=["anydesk", "virus detected"])
                self.assertFalse(sw.should_confirm(fp, self.cfg))

    def test_confirms_on_phone_plus_remote_tool(self):
        fp = sw.Fingerprint(domain="x.sbs", content_score=5, fetched=True,
                            http_status=200, markers=["anydesk"],
                            phones=["+18335550142"])
        self.assertTrue(sw.should_confirm(fp, self.cfg))

    def test_weak_markers_cannot_stack_to_a_confirmation(self):
        """
        Regression, observed live: suncoastcreditunion.com - a real credit
        union - surfaced as a candidate. A legitimate security-awareness page
        can carry "security alert" + "your password" + "call the number",
        which is exactly the threshold. At least one marker must describe
        something only a scam page does.
        """
        fp = sw.Fingerprint(domain="suncoastcreditunion.com", content_score=6,
                            fetched=True, http_status=200,
                            markers=["security alert", "your password",
                                     "call the number"])
        self.assertEqual(fp.strong_markers, [])
        self.assertFalse(sw.should_confirm(fp, self.cfg))

    def test_one_strong_marker_unlocks_the_threshold(self):
        fp = sw.Fingerprint(domain="evil.sbs", content_score=6, fetched=True,
                            http_status=200,
                            markers=["virus detected", "security alert"])
        self.assertIn("virus detected", fp.strong_markers)
        self.assertTrue(sw.should_confirm(fp, self.cfg))

    def test_strong_marker_set_is_weight_derived(self):
        self.assertIn("anydesk", sw.STRONG_MARKERS)
        self.assertIn("virus detected", sw.STRONG_MARKERS)
        self.assertNotIn("toll-free", sw.STRONG_MARKERS)
        self.assertNotIn("error code", sw.STRONG_MARKERS)

    def test_confirms_on_strong_content_score(self):
        fp = sw.Fingerprint(domain="x.sbs", content_score=12, fetched=True,
                            http_status=200,
                            markers=["virus detected", "call immediately"])
        self.assertTrue(sw.should_confirm(fp, self.cfg))

    def test_score_is_the_sum_of_both_halves(self):
        fp = sw.Fingerprint(domain="x.sbs", heuristic_score=3, content_score=4)
        self.assertEqual(fp.score, 7)


class TestStore(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.store = sw.Store(Path(self.tmp.name) / "t.db")

    def tearDown(self):
        self.store.close()
        self.tmp.cleanup()

    def test_first_seen_survives_reprocessing(self):
        self.store.upsert("evil.sbs", "ct:test", score=3)
        first = self.store.con.execute(
            "SELECT first_seen FROM domains WHERE domain=?",
            ("evil.sbs",)).fetchone()["first_seen"]
        self.store.upsert("evil.sbs", "urlscan:test", score=9)
        row = self.store.con.execute(
            "SELECT * FROM domains WHERE domain=?", ("evil.sbs",)).fetchone()
        self.assertEqual(row["first_seen"], first)
        self.assertEqual(row["score"], 9)
        self.assertEqual(row["source"], "urlscan:test")

    def test_seen(self):
        self.assertFalse(self.store.seen("evil.sbs"))
        self.store.upsert("evil.sbs", "ct:test")
        self.assertTrue(self.store.seen("evil.sbs"))

    def test_phone_ioc_accumulates_across_domains(self):
        self.store.record_phones(["+18335550142"], "a.sbs")
        self.store.record_phones(["+18335550142"], "b.sbs")
        self.store.record_phones(["+18335550142"], "a.sbs")
        row = self.store.all_phones()[0]
        self.assertEqual(row["hits"], 3)
        self.assertEqual(sorted(row["domains"].split(",")), ["a.sbs", "b.sbs"])

    def test_stats(self):
        self.store.upsert("a.sbs", "ct:test")
        self.store.upsert("b.sbs", "ct:test")
        self.store.mark_reported("b.sbs")
        stats = self.store.stats()
        self.assertEqual(stats["domains"], 2)
        self.assertEqual(stats["confirmed"], 1)


class TestFeedParsing(unittest.TestCase):
    def test_extracts_host_from_url_or_bare_domain(self):
        cases = {
            "http://fake-support.sbs/anz/index.html": "fake-support.sbs",
            "https://Live-Support.XYZ:8443/x": "live-support.xyz",
            "evil-helpdesk.click": "evil-helpdesk.click",
            "evil.sbs/path/here": "evil.sbs",
        }
        for line, expected in cases.items():
            with self.subTest(line=line):
                self.assertEqual(sw.host_from_feed_line(line), expected)

    def test_ignores_blanks_comments_and_junk(self):
        for line in ("", "   ", "# comment", "not a domain", "http://"):
            with self.subTest(line=line):
                self.assertEqual(sw.host_from_feed_line(line), "")

    def test_matchers_cover_hyphen_and_joined_forms(self):
        matchers = sw.build_feed_matchers(sw.DEFAULT_CONFIG)
        self.assertIn("windows-defender", matchers)
        self.assertIn("windowsdefender", matchers)
        self.assertIn("anydesk", matchers)
        # short shortcodes must not become 2-char matchers that hit everything
        self.assertTrue(all(len(m) >= 4 for m in matchers))


class TestCtRefinement(unittest.TestCase):
    """
    Broad crt.sh terms are a workaround for the service degrading on selective
    patterns, so the local refinement is what keeps results specific.
    """

    ROWS = [
        {"entry_timestamp": "2026-08-16T10:00:00",
         "name_value": "1997-defender--94.lpme.co.uk"},          # car dealer
        {"entry_timestamp": "2026-08-16T09:00:00",
         "name_value": "windows-defender-alert.sbs"},            # target
        {"entry_timestamp": "2026-08-16T08:00:00",
         "name_value": "*.defender-alert-support.click"},        # target
        {"entry_timestamp": "2026-08-16T07:00:00",
         "name_value": "sugar-defender-reviews.pages.dev"},      # unrelated
    ]

    class FakeSession:
        def __init__(self, rows):
            self.rows = rows

        def get(self, url, params=None, timeout=None, **kw):
            rows = self.rows

            class R:
                status_code = 200

                def raise_for_status(self): pass

                def json(self): return rows
            return R()

    def setUp(self):
        self._delay = sw.CT_QUERY_DELAY
        sw.CT_QUERY_DELAY = 0

    def tearDown(self):
        sw.CT_QUERY_DELAY = self._delay

    def _run(self, require_refine):
        health = sw.SourceHealth("ct")
        return list(sw.ct_candidates(
            self.FakeSession(self.ROWS), ["defender"],
            ["windows-defender", "defender-alert"], 50, health,
            require_refine=require_refine)), health

    def test_refinement_gates_out_unrelated_hosts(self):
        got, health = self._run(True)
        domains = [d for d, _ in got]
        self.assertIn("windows-defender-alert.sbs", domains)
        self.assertIn("defender-alert-support.click", domains)
        self.assertNotIn("1997-defender--94.lpme.co.uk", domains)
        self.assertNotIn("sugar-defender-reviews.pages.dev", domains)
        self.assertEqual(health.yielded, 2)

    def test_source_label_records_the_refined_signature(self):
        got, _ = self._run(True)
        labels = dict(got)
        self.assertEqual(labels["windows-defender-alert.sbs"],
                         "ct:defender+windows-defender")

    def test_wildcard_prefix_is_stripped(self):
        domains = [d for d, _ in self._run(True)[0]]
        self.assertNotIn("*.defender-alert-support.click", domains)

    def test_disabling_refinement_keeps_everything(self):
        domains = [d for d, _ in self._run(False)[0]]
        self.assertEqual(len(domains), 4)

    def test_limit_counts_kept_domains_not_rows_scanned(self):
        """Precision must not cost recall: noise rows must not consume limit."""
        health = sw.SourceHealth("ct")
        got = list(sw.ct_candidates(
            self.FakeSession(self.ROWS), ["defender"],
            ["windows-defender", "defender-alert"], 2, health,
            require_refine=True))
        self.assertEqual(len(got), 2)


class TestBodyDecoding(unittest.TestCase):
    """
    Regression, crashed a live pass: read_body used resp.apparent_encoding as
    its fallback, which reads resp.content and raises RuntimeError once the
    body has been consumed by iter_content. Every server that omits a charset
    from Content-Type took down the entire pass, not just that candidate.
    """

    def test_decodes_utf8_without_a_header_charset(self):
        self.assertEqual(sw.decode_body(b"<p>caf\xc3\xa9</p>", None),
                         "<p>café</p>")

    def test_honours_header_charset(self):
        self.assertEqual(sw.decode_body(b"<p>caf\xe9</p>", "iso-8859-1"),
                         "<p>café</p>")

    def test_sniffs_meta_charset_when_header_is_absent(self):
        raw = b'<meta charset="iso-8859-1"><p>caf\xe9</p>'
        self.assertIn("café", sw.decode_body(raw, None))

    def test_unknown_codec_falls_back_instead_of_raising(self):
        self.assertIsInstance(sw.decode_body(b"hello", "no-such-codec"), str)

    def test_undecodable_bytes_never_raise(self):
        self.assertIsInstance(sw.decode_body(b"\xff\xfe\x00bad", None), str)

    def test_empty_body(self):
        self.assertEqual(sw.decode_body(b"", None), "")

    def test_read_body_does_not_touch_apparent_encoding(self):
        """The real failure: apparent_encoding raises after streaming."""
        class Consumed:
            encoding = None
            headers = {}

            def iter_content(self, n):
                yield b"<p>hi</p>"

            @property
            def apparent_encoding(self):
                raise RuntimeError(
                    "The content for this response was already consumed")
        self.assertEqual(sw.read_body(Consumed()), "<p>hi</p>")


class TestUrlscanDateFilter(unittest.TestCase):
    """
    urlscan's index reaches back years; these pages live for hours. Of 14
    unfiltered hits fetched during testing, 10 returned a hosting "site not
    found" stub, so recency is not a nicety.
    """

    def test_wraps_and_constrains(self):
        self.assertEqual(sw.apply_date_filter('page.url:"anydesk"', 7),
                         '(page.url:"anydesk") AND date:>now-7d')

    def test_parenthesised_so_or_queries_are_not_broken(self):
        out = sw.apply_date_filter('a:"x" OR b:"y"', 3)
        self.assertTrue(out.startswith('(a:"x" OR b:"y")'))

    def test_respects_an_explicit_date_filter(self):
        q = 'page.url:"anydesk" AND date:>now-1d'
        self.assertEqual(sw.apply_date_filter(q, 7), q)

    def test_disabled_when_zero_or_negative(self):
        self.assertEqual(sw.apply_date_filter('x:"y"', 0), 'x:"y"')
        self.assertEqual(sw.apply_date_filter('x:"y"', -1), 'x:"y"')


class TestArchiveFallback(unittest.TestCase):
    """
    The live page is usually gone by the time a candidate surfaces, so the
    saved DOM is what turns a dead lead into reportable evidence.
    """

    SCAM_DOM = ("<html><head><title>Windows Defender Alert</title></head><body>"
                "<h1>Virus detected</h1><p>Do not restart your PC. "
                "Call <a href='tel:+18335550142'>1-833-555-0142</a> and "
                "download AnyDesk so a technician can share your screen.</p>"
                "</body></html>")

    class FakeSession:
        def __init__(self, status=200, text=""):
            self.status, self.text_ = status, text
            self.headers_seen = None

        def get(self, url, timeout=None, headers=None, **kw):
            self.headers_seen = headers
            outer = self

            class R:
                status_code = outer.status
                text = outer.text_
            return R()

    def test_scores_archived_dom_and_marks_provenance(self):
        sess = self.FakeSession(200, self.SCAM_DOM)
        fp = sw.fingerprint_archive(sess, "evil.sbs", "uuid-1", "key",
                                    sw.DEFAULT_CONFIG)
        self.assertIsNotNone(fp)
        self.assertEqual(fp.evidence, "urlscan-archive")
        self.assertEqual(fp.evidence_ref, "uuid-1")
        self.assertIn("anydesk", fp.markers)
        self.assertIn("+18335550142", fp.phones)
        self.assertTrue(sw.should_confirm(fp, sw.DEFAULT_CONFIG))

    def test_sends_the_api_key(self):
        sess = self.FakeSession(200, self.SCAM_DOM)
        sw.fingerprint_archive(sess, "evil.sbs", "u", "secret",
                               sw.DEFAULT_CONFIG)
        self.assertEqual(sess.headers_seen.get("API-Key"), "secret")

    def test_requires_uuid_and_key(self):
        sess = self.FakeSession(200, self.SCAM_DOM)
        self.assertIsNone(sw.fingerprint_archive(sess, "e.sbs", "", "key",
                                                 sw.DEFAULT_CONFIG))
        self.assertIsNone(sw.fingerprint_archive(sess, "e.sbs", "u", "",
                                                 sw.DEFAULT_CONFIG))

    def test_anonymous_403_yields_nothing(self):
        sess = self.FakeSession(403, '{"warning": "You\'re not logged in!"}')
        self.assertIsNone(sw.fingerprint_archive(sess, "e.sbs", "u", "key",
                                                 sw.DEFAULT_CONFIG))

    def test_empty_dom_yields_nothing(self):
        sess = self.FakeSession(200, "")
        self.assertIsNone(sw.fingerprint_archive(sess, "e.sbs", "u", "key",
                                                 sw.DEFAULT_CONFIG))

    def test_reports_state_archived_provenance(self):
        fp = sw.Fingerprint(domain="e.sbs", content_score=9, fetched=True,
                            http_status=200, markers=["anydesk"],
                            evidence="urlscan-archive", evidence_ref="u-9")
        md = sw.build_markdown("e.sbs", fp, sw.Attribution(), "urlscan:x", "t")
        self.assertIn("urlscan saved DOM", md)
        self.assertIn("u-9", md)

        live = sw.Fingerprint(domain="e.sbs", content_score=9, fetched=True,
                              http_status=200, markers=["anydesk"])
        self.assertIn("live fetch", sw.build_markdown(
            "e.sbs", live, sw.Attribution(), "ct:x", "t"))


class TestCandidateMerging(unittest.TestCase):
    def test_archive_reference_is_kept_from_a_later_source(self):
        c = sw.Candidate(source="ct:defender")
        self.assertEqual(c.urlscan_uuid, "")
        c.urlscan_uuid = "uuid-2"
        self.assertEqual(c.source, "ct:defender")
        self.assertEqual(c.urlscan_uuid, "uuid-2")


class TestStoreMeta(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.store = sw.Store(Path(self.tmp.name) / "t.db")

    def tearDown(self):
        self.store.close()
        self.tmp.cleanup()

    def test_roundtrip_and_default(self):
        self.assertEqual(self.store.get_meta("missing", "fallback"), "fallback")
        self.store.set_meta("feed:x:etag", 'W/"abc"')
        self.assertEqual(self.store.get_meta("feed:x:etag"), 'W/"abc"')

    def test_overwrite(self):
        self.store.set_meta("k", "1")
        self.store.set_meta("k", "2")
        self.assertEqual(self.store.get_meta("k"), "2")


class TestSourceHealth(unittest.TestCase):
    def test_skipped(self):
        self.assertIn("skipped", sw.SourceHealth("ct", skipped=True).summary())

    def test_total_failure_is_loud(self):
        health = sw.SourceHealth("ct", queries=5, failures=5)
        self.assertFalse(health.ok)
        self.assertIn("FAILED", health.summary())

    def test_empty_but_working_is_distinguished_from_failure(self):
        health = sw.SourceHealth("ct", queries=5, failures=0, yielded=0)
        self.assertTrue(health.ok)
        self.assertIn("ok-but-empty", health.summary())

    def test_cached_source_is_not_reported_as_broken(self):
        health = sw.SourceHealth("feeds", queries=0, cached=2)
        self.assertIn("cached", health.summary())
        self.assertNotIn("NO-QUERIES", health.summary())

    def test_partial_failure_reported(self):
        health = sw.SourceHealth("ct", queries=5, failures=2, yielded=7)
        self.assertTrue(health.ok)
        summary = health.summary()
        self.assertIn("7", summary)
        self.assertIn("2/5", summary)


class TestRdapParsing(unittest.TestCase):
    SAMPLE = {
        "entities": [{
            "roles": ["registrar"],
            "vcardArray": ["vcard", [
                ["version", {}, "text", "4.0"],
                ["fn", {}, "text", "NameCheap, Inc."],
            ]],
            "entities": [{
                "roles": ["abuse"],
                "vcardArray": ["vcard", [
                    ["fn", {}, "text", "Abuse Department"],
                    ["email", {}, "text", "abuse@namecheap.com"],
                ]],
            }],
        }],
        "events": [{"eventAction": "registration",
                    "eventDate": "2026-03-01T10:00:00Z"}],
    }

    def test_extracts_registrar_and_nested_abuse_email(self):
        name, email_addr = sw.registrar_from_rdap(self.SAMPLE)
        self.assertEqual(name, "NameCheap, Inc.")
        self.assertEqual(email_addr, "abuse@namecheap.com")

    def test_tolerates_malformed_vcards(self):
        for junk in ({}, {"entities": "nope"}, {"entities": [{"vcardArray": []}]},
                     {"entities": [{"vcardArray": ["vcard", [["fn"], None, 5]]}]}):
            with self.subTest(junk=junk):
                self.assertEqual(sw.registrar_from_rdap(junk), ("", ""))


class TestConfig(unittest.TestCase):
    def test_writes_defaults_when_absent(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "cfg.json"
            cfg = sw.load_config(path)
            self.assertTrue(path.exists())
            self.assertIn("ct_keywords", cfg)

    def test_user_values_merge_over_defaults(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "cfg.json"
            path.write_text(json.dumps({
                "confirm_threshold": 99,
                "registrar_abuse": {"newreg": "abuse@newreg.test"},
            }))
            cfg = sw.load_config(path)
            self.assertEqual(cfg["confirm_threshold"], 99)
            self.assertEqual(cfg["registrar_abuse"]["newreg"], "abuse@newreg.test")
            # defaults still present
            self.assertIn("namecheap", cfg["registrar_abuse"])
            self.assertIn("ct_keywords", cfg)

    def test_broken_config_falls_back(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "cfg.json"
            path.write_text("{not json")
            self.assertIn("ct_keywords", sw.load_config(path))

    def test_defaults_are_not_mutated_by_load(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "cfg.json"
            path.write_text(json.dumps({"registrar_abuse": {"x": "y@z.test"}}))
            sw.load_config(path)
            self.assertNotIn("x", sw.DEFAULT_CONFIG["registrar_abuse"])


class TestReportRendering(unittest.TestCase):
    def _fp(self):
        return sw.Fingerprint(
            domain="live-support-defender.sbs", heuristic_score=3,
            content_score=11, fetched=True,
            markers=["anydesk", "virus detected", "call immediately"],
            phones=["+18335550142"], brands=["anz"], ip="203.0.113.10",
            title="Live Support", final_url="https://live-support-defender.sbs/",
            http_status=200)

    def test_markdown_contains_evidence(self):
        att = sw.Attribution(registrar="NameCheap, Inc.",
                             registrar_abuse="abuse@namecheap.com")
        md = sw.build_markdown("live-support-defender.sbs", self._fp(), att,
                               "ct:live-support", "20260316T101500Z")
        for needle in ("live-support-defender.sbs", "+18335550142", "anydesk",
                       "abuse@namecheap.com", "203.0.113.10", "ic3.gov"):
            self.assertIn(needle, md)

    def test_eml_is_a_parseable_message(self):
        import email as email_mod
        import email.policy
        att = sw.Attribution(registrar_abuse="abuse@namecheap.com",
                             host_abuse="abuse@netlify.com")
        raw = sw.build_eml("live-support-defender.sbs", self._fp(),
                           att, sw.DEFAULT_CONFIG, "report.md")
        msg = email_mod.message_from_bytes(raw, policy=email_mod.policy.default)
        self.assertIn("abuse@namecheap.com", msg["To"])
        self.assertIn("abuse@netlify.com", msg["To"])
        self.assertTrue(msg["Date"])
        self.assertIn("live-support-defender.sbs", msg["Subject"])
        self.assertIn("+18335550142", msg.get_content())

    def test_eml_claims_only_what_the_markers_support(self):
        """An abuse draft must not assert remote-access tooling it never saw."""
        import email as email_mod
        import email.policy

        def body_for(fp):
            raw = sw.build_eml(fp.domain, fp, sw.Attribution(
                registrar_abuse="a@b.test"), sw.DEFAULT_CONFIG, "r.md")
            return email_mod.message_from_bytes(
                raw, policy=email_mod.policy.default).get_content()

        with_tool = body_for(sw.Fingerprint(
            domain="a.sbs", markers=["anydesk"], phones=["+18335550142"]))
        self.assertIn("remote-access software", with_tool)

        without_tool = body_for(sw.Fingerprint(
            domain="b.sbs", markers=["virus detected"], phones=["+18335550142"]))
        self.assertNotIn("AnyDesk / TeamViewer", without_tool)
        self.assertIn("telephone number", without_tool)

        bare = body_for(sw.Fingerprint(domain="c.sbs", markers=["virus detected"]))
        self.assertNotIn("AnyDesk / TeamViewer", bare)

    def test_csv_round_trips_commas_in_fields(self):
        import csv as csv_mod
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "out.csv"
            sw.append_csv(path, ["ts", "evil.sbs", "ct:x", 9, 3,
                                 "203.0.113.10", "Registrar, Inc.",
                                 "abuse@r.test", "Host", "abuse@h.test",
                                 "+18335550142", "anz", "Hi"])
            with path.open(encoding="utf-8", newline="") as fh:
                rows = list(csv_mod.reader(fh))
        self.assertEqual(rows[0][0], "timestamp")
        self.assertEqual(rows[1][6], "Registrar, Inc.")
        self.assertEqual(len(rows[1]), len(rows[0]))


class TestArgParsing(unittest.TestCase):
    def test_defaults(self):
        args = sw.build_parser().parse_args([])
        self.assertFalse(args.loop)
        self.assertEqual(args.interval, 300)
        self.assertEqual(args.out, Path("out"))

    def test_flags(self):
        args = sw.build_parser().parse_args(
            ["--loop", "--interval", "60", "--no-fingerprint", "-v"])
        self.assertTrue(args.loop)
        self.assertEqual(args.interval, 60)
        self.assertTrue(args.no_fingerprint)


if __name__ == "__main__":
    unittest.main()
