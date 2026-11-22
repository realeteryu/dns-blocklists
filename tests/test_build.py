import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from scripts.build import (
    BuildError,
    apply_allowlist,
    build_blocklist,
    is_public_suffix,
    normalize_domain,
    normalize_psl_rule,
    optimize_domains,
    parse_adblock,
    parse_domain_lines,
    parse_hosts,
    parse_rpz,
)


class TestNormalizeDomain(unittest.TestCase):

    def test_lowercase(self):
        self.assertEqual(normalize_domain("Example.COM"), "example.com")

    def test_trailing_dot(self):
        self.assertEqual(normalize_domain("example.com."), "example.com")

    def test_wildcard(self):
        self.assertEqual(normalize_domain("*.example.com"), "example.com")

    def test_idn(self):
        self.assertEqual(normalize_domain("żółć.pl"), "xn--kda4b0koi.pl")

    def test_reject_single_label(self):
        self.assertIsNone(normalize_domain("localhost"))

    def test_reject_invalid_domain(self):
        self.assertIsNone(normalize_domain("-invalid.com"))

    def test_reject_empty_label(self):
        self.assertIsNone(normalize_domain("example..com"))

    def test_reject_underscore(self):
        self.assertIsNone(normalize_domain("bad_name.example.com"))


class TestNormalizePslRule(unittest.TestCase):

    def test_single_label_rule(self):
        self.assertEqual(normalize_psl_rule("com"), "com")

    def test_multilevel_rule(self):
        self.assertEqual(normalize_psl_rule("co.uk"), "co.uk")

    def test_wildcard_base(self):
        self.assertEqual(normalize_psl_rule("ck"), "ck")

    def test_idn_rule(self):
        self.assertEqual(
            normalize_psl_rule("公司.cn"),
            "xn--55qx5d.cn",
        )

    def test_invalid_rule(self):
        self.assertIsNone(normalize_psl_rule("-invalid"))


class TestDomainParser(unittest.TestCase):

    def test_plain_domains(self):
        text = """
        example.com
        ads.example.org
        """

        self.assertEqual(
            parse_domain_lines(text),
            {"example.com", "ads.example.org"},
        )

    def test_comments_and_wildcards(self):
        text = """
        # comment
        *.example.com
        ads.example.org # inline comment
        """

        self.assertEqual(
            parse_domain_lines(text),
            {"example.com", "ads.example.org"},
        )

    def test_hosts_style_in_domain_list(self):
        text = """
        0.0.0.0 ads.example.com
        127.0.0.1 tracker.example.org
        """

        self.assertEqual(
            parse_domain_lines(text),
            {"ads.example.com", "tracker.example.org"},
        )

    def test_adblock_style_domain(self):
        self.assertEqual(
            parse_domain_lines("||ads.example.com^\n"),
            {"ads.example.com"},
        )

    def test_duplicate_domains(self):
        text = """
        example.com
        EXAMPLE.COM
        example.com.
        """

        self.assertEqual(
            parse_domain_lines(text),
            {"example.com"},
        )


class TestHostsParser(unittest.TestCase):

    def test_ipv4(self):
        text = """
        0.0.0.0 ads.example.com
        127.0.0.1 tracker.example.org
        """

        self.assertEqual(
            parse_hosts(text),
            {"ads.example.com", "tracker.example.org"},
        )

    def test_ipv6(self):
        text = """
        ::1 localhost
        ::1 ads.example.com
        """

        self.assertEqual(
            parse_hosts(text),
            {"ads.example.com"},
        )

    def test_multiple_domains_on_one_line(self):
        text = """
        0.0.0.0 ads.example.com tracker.example.com
        """

        self.assertEqual(
            parse_hosts(text),
            {"ads.example.com", "tracker.example.com"},
        )

    def test_invalid_ip_is_ignored(self):
        self.assertEqual(
            parse_hosts("invalid-ip ads.example.com\n"),
            set(),
        )

    def test_inline_comment(self):
        self.assertEqual(
            parse_hosts("0.0.0.0 ads.example.com # comment\n"),
            {"ads.example.com"},
        )


class TestAdblockParser(unittest.TestCase):

    def test_simple_blocking_rule(self):
        text = """
        [Adblock Plus 2.0]
        ||ads.example.com^
        ||tracker.example.org^
        """

        self.assertEqual(
            parse_adblock(text),
            {"ads.example.com", "tracker.example.org"},
        )

    def test_exception_and_cosmetic_rules_are_ignored(self):
        text = """
        [Adblock Plus 2.0]
        ||ads.example.com^
        @@||allowed.example.com^
        example.com##.advertisement
        """

        self.assertEqual(
            parse_adblock(text),
            {"ads.example.com"},
        )

    def test_url_rules_are_ignored(self):
        text = """
        [Adblock Plus 2.0]
        ||example.com/ads/banner.js
        """

        self.assertEqual(parse_adblock(text), set())

    def test_subdomain_rule(self):
        text = """
        [Adblock Plus 2.0]
        ||ads.example.com^
        """

        self.assertEqual(
            parse_adblock(text),
            {"ads.example.com"},
        )

    def test_empty_filterlist(self):
        self.assertEqual(
            parse_adblock("[Adblock Plus 2.0]\n"),
            set(),
        )


class TestRpzParser(unittest.TestCase):

    def test_blocking_rpz_records(self):
        text = """
        $ORIGIN rpz.example.
        $TTL 60
        @ IN SOA localhost. hostmaster.localhost. (
            1 3600 600 86400 60
        )
        @ IN NS localhost.
        example.com CNAME .
        ads.example.org CNAME rpz-drop.
        allowed.example.net CNAME target.example.net.
        """

        self.assertEqual(
            parse_rpz(text),
            {"example.com", "ads.example.org"},
        )

    def test_all_supported_blocking_targets(self):
        text = """
        $ORIGIN rpz.example.
        $TTL 60
        @ IN SOA localhost. hostmaster.localhost. (
            1 3600 600 86400 60
        )
        @ IN NS localhost.
        a.example.com CNAME .
        b.example.com CNAME rpz-drop.
        c.example.com CNAME rpz-nxdomain.
        d.example.com CNAME rpz-nodata.
        e.example.com CNAME rpz-tcp-only.
        f.example.com CNAME allowed.example.net.
        """

        self.assertEqual(
            parse_rpz(text),
            {
                "a.example.com",
                "b.example.com",
                "c.example.com",
                "d.example.com",
                "e.example.com",
            },
        )

    def test_invalid_rpz_raises_build_error(self):
        with self.assertRaises(BuildError):
            parse_rpz("This is not a DNS zone.")

    def test_missing_soa_raises_build_error(self):
        text = """
        $ORIGIN rpz.example.
        @ IN NS localhost.
        example.com CNAME .
        """

        with self.assertRaises(BuildError):
            parse_rpz(text)


class TestAllowlist(unittest.TestCase):

    def test_domain_and_subdomains_are_removed(self):
        domains = {
            "example.com",
            "ads.example.com",
            "tracker.example.com",
            "other.com",
        }

        self.assertEqual(
            apply_allowlist(domains, {"example.com"}),
            {"other.com"},
        )

    def test_similar_domain_is_not_removed(self):
        domains = {"example.com", "notexample.com"}

        self.assertEqual(
            apply_allowlist(domains, {"example.com"}),
            {"notexample.com"},
        )

    def test_empty_allowlist_preserves_domains(self):
        domains = {"example.com", "ads.example.org"}

        self.assertEqual(
            apply_allowlist(domains, set()),
            domains,
        )


class TestOptimization(unittest.TestCase):

    def test_redundant_subdomains_are_removed(self):
        domains = {
            "example.com",
            "ads.example.com",
            "tracker.example.com",
            "other.com",
        }

        self.assertEqual(
            optimize_domains(domains),
            {"example.com", "other.com"},
        )

    def test_nested_domains_are_optimized(self):
        domains = {
            "example.com",
            "ads.example.com",
            "banner.ads.example.com",
            "other.example.org",
        }

        self.assertEqual(
            optimize_domains(domains),
            {"example.com", "other.example.org"},
        )

    def test_unrelated_domains_are_preserved(self):
        domains = {"example.com", "example.org", "example.net"}

        self.assertEqual(optimize_domains(domains), domains)

    def test_empty_input(self):
        self.assertEqual(optimize_domains(set()), set())


class TestPublicSuffixList(unittest.TestCase):

    def setUp(self):
        self.rules = (
            {"com", "org", "net", "co.uk", "ck"},
            {"ck"},
            {"www.ck"},
        )

    def test_common_suffix(self):
        self.assertTrue(is_public_suffix("com", self.rules))

    def test_multilevel_suffix(self):
        self.assertTrue(is_public_suffix("co.uk", self.rules))

    def test_regular_domain(self):
        self.assertFalse(is_public_suffix("example.com", self.rules))

    def test_wildcard_suffix(self):
        self.assertTrue(is_public_suffix("a.ck", self.rules))

    def test_wildcard_child_is_not_suffix(self):
        self.assertFalse(is_public_suffix("x.a.ck", self.rules))

    def test_exception_rule(self):
        self.assertFalse(is_public_suffix("www.ck", self.rules))

    def test_exception_child(self):
        self.assertFalse(is_public_suffix("x.www.ck", self.rules))


class TestBuildSafety(unittest.TestCase):

    def test_failed_source_does_not_overwrite_existing_output(self):
        with tempfile.TemporaryDirectory() as directory:
            output_file = Path(directory) / "blocklist.txt"
            output_file.write_text(
                "previous.example.com\n",
                encoding="utf-8",
            )

            config = {
                "public_suffix_list": "https://example.com/psl",
                "sources": {
                    "domains": ["https://example.com/list.txt"],
                },
            }

            rules = (
                {"com", "org", "net"},
                set(),
                set(),
            )

            with (
                patch("scripts.build.OUTPUT_FILE", output_file),
                patch("scripts.build.load_configuration", return_value=config),
                patch("scripts.build.load_public_suffix_list", return_value=rules),
                patch("scripts.build.download_text", return_value="not-a-domain"),
            ):
                with self.assertRaises(BuildError):
                    build_blocklist()

            self.assertEqual(
                output_file.read_text(encoding="utf-8"),
                "previous.example.com\n",
            )


if __name__ == "__main__":
    unittest.main()
