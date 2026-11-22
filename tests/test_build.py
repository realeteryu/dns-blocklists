import unittest

from scripts.build import (
    apply_allowlist,
    is_public_suffix,
    normalize_domain,
    optimize_domains,
    parse_adblock,
    parse_domain_lines,
    parse_hosts,
    parse_rpz,
)


class TestNormalizeDomain(unittest.TestCase):

    def test_lowercase(self):
        self.assertEqual(
            normalize_domain("Example.COM"),
            "example.com",
        )

    def test_trailing_dot(self):
        self.assertEqual(
            normalize_domain("example.com."),
            "example.com",
        )

    def test_wildcard(self):
        self.assertEqual(
            normalize_domain("*.example.com"),
            "example.com",
        )

    def test_idn(self):
        self.assertEqual(
            normalize_domain("żółć.pl"),
            "xn--kda4b0koi.pl",
        )

    def test_reject_single_label(self):
        self.assertIsNone(
            normalize_domain("localhost")
        )

    def test_reject_invalid_domain(self):
        self.assertIsNone(
            normalize_domain("-invalid.com")
        )


class TestDomainParser(unittest.TestCase):

    def test_plain_domains(self):
        text = """
        example.com
        ads.example.org
        """

        self.assertEqual(
            parse_domain_lines(text),
            {
                "example.com",
                "ads.example.org",
            },
        )

    def test_comments_and_wildcards(self):
        text = """
        # comment
        *.example.com
        ads.example.org # inline comment
        """

        self.assertEqual(
            parse_domain_lines(text),
            {
                "example.com",
                "ads.example.org",
            },
        )

    def test_hosts_style_in_domain_list(self):
        text = """
        0.0.0.0 ads.example.com
        127.0.0.1 tracker.example.org
        """

        self.assertEqual(
            parse_domain_lines(text),
            {
                "ads.example.com",
                "tracker.example.org",
            },
        )


class TestHostsParser(unittest.TestCase):

    def test_ipv4(self):
        text = """
        0.0.0.0 ads.example.com
        127.0.0.1 tracker.example.org
        """

        self.assertEqual(
            parse_hosts(text),
            {
                "ads.example.com",
                "tracker.example.org",
            },
        )

    def test_ipv6(self):
        text = """
        ::1 localhost
        ::1 ads.example.com
        """

        self.assertEqual(
            parse_hosts(text),
            {
                "ads.example.com",
            },
        )

    def test_multiple_domains_on_one_line(self):
        text = """
        0.0.0.0 ads.example.com tracker.example.com
        """

        self.assertEqual(
            parse_hosts(text),
            {
                "ads.example.com",
                "tracker.example.com",
            },
        )

    def test_invalid_ip_is_ignored(self):
        text = """
        invalid-ip ads.example.com
        """

        self.assertEqual(
            parse_hosts(text),
            set(),
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
            {
                "ads.example.com",
                "tracker.example.org",
            },
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
            {
                "ads.example.com",
            },
        )

    def test_url_rules_are_ignored(self):
        text = """
        [Adblock Plus 2.0]
        ||example.com/ads/banner.js
        """

        self.assertEqual(
            parse_adblock(text),
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
            {
                "example.com",
                "ads.example.org",
            },
        )

    def test_invalid_rpz_raises_error(self):
        with self.assertRaises(Exception):
            parse_rpz("This is not a DNS zone.")


class TestAllowlist(unittest.TestCase):

    def test_domain_and_subdomains_are_removed(self):
        domains = {
            "example.com",
            "ads.example.com",
            "tracker.example.com",
            "other.com",
        }

        allowlist = {
            "example.com",
        }

        self.assertEqual(
            apply_allowlist(domains, allowlist),
            {
                "other.com",
            },
        )

    def test_similar_domain_is_not_removed(self):
        domains = {
            "example.com",
            "notexample.com",
        }

        allowlist = {
            "example.com",
        }

        self.assertEqual(
            apply_allowlist(domains, allowlist),
            {
                "notexample.com",
            },
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
            {
                "example.com",
                "other.com",
            },
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
            {
                "example.com",
                "other.example.org",
            },
        )

    def test_unrelated_domains_are_preserved(self):
        domains = {
            "example.com",
            "example.org",
            "example.net",
        }

        self.assertEqual(
            optimize_domains(domains),
            domains,
        )


class TestPublicSuffixList(unittest.TestCase):

    def setUp(self):
        self.rules = (
            {
                "com",
                "org",
                "net",
                "co.uk",
                "ck",
            },
            {
                "ck",
            },
            {
                "www.ck",
            },
        )

    def test_common_suffix(self):
        self.assertTrue(
            is_public_suffix("com", self.rules)
        )

    def test_multi_level_suffix(self):
        self.assertTrue(
            is_public_suffix("co.uk", self.rules)
        )

    def test_regular_domain(self):
        self.assertFalse(
            is_public_suffix("example.com", self.rules)
        )

    def test_wildcard_suffix(self):
        self.assertTrue(
            is_public_suffix("a.ck", self.rules)
        )

    def test_exception_rule(self):
        self.assertFalse(
            is_public_suffix("www.ck", self.rules)
        )


if __name__ == "__main__":
    unittest.main()
