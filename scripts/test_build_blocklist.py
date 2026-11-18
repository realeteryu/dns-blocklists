import unittest

from build_blocklist import (
    normalize_domain,
    parse_source_line,
    optimize_blocklist,
)


class TestNormalizeDomain(unittest.TestCase):

    def test_normalizes_case_and_trailing_dot(self):
        self.assertEqual(
            normalize_domain("Example.PL."),
            "example.pl",
        )

    def test_accepts_valid_subdomain(self):
        self.assertEqual(
            normalize_domain("api.example.com"),
            "api.example.com",
        )

    def test_rejects_invalid_domain(self):
        invalid_domains = [
            "",
            "example",
            "-example.com",
            "example-.com",
            "example..com",
            "example.com/path",
            "example.com:443",
            "example.com?",
            "example com",
        ]

        for domain in invalid_domains:
            with self.subTest(domain=domain):
                self.assertIsNone(normalize_domain(domain))

    def test_rejects_ipv4(self):
        self.assertIsNone(normalize_domain("192.0.2.1"))

    def test_rejects_ipv6(self):
        self.assertIsNone(
            normalize_domain("2001:db8::1")
        )

    def test_rejects_ignored_domains(self):
        ignored = [
            "localhost",
            "local",
            "example.com",
            "example.net",
            "example.org",
        ]

        for domain in ignored:
            with self.subTest(domain=domain):
                self.assertIsNone(normalize_domain(domain))


class TestSourceParsing(unittest.TestCase):

    def test_ignores_full_line_comments(self):
        self.assertEqual(
            parse_source_line("# komentarz"),
            [],
        )

    def test_parses_hosts_entry(self):
        self.assertEqual(
            parse_source_line("0.0.0.0 ads.example.com"),
            ["ads.example.com"],
        )

    def test_parses_hosts_aliases(self):
        self.assertEqual(
            parse_source_line(
                "127.0.0.1 ads.example.com tracker.example.com"
            ),
            ["ads.example.com", "tracker.example.com"],
        )

    def test_ignores_hosts_inline_comment(self):
        self.assertEqual(
            parse_source_line(
                "0.0.0.0 ads.example.com # komentarz"
            ),
            ["ads.example.com"],
        )

    def test_parses_adblock_domain_rule(self):
        self.assertEqual(
            parse_source_line("||ads.example.com^"),
            ["ads.example.com"],
        )

    def test_ignores_adblock_exception(self):
        self.assertEqual(
            parse_source_line("@@||example.com^"),
            [],
        )

    def test_parses_domain_wildcard(self):
        self.assertEqual(
            parse_source_line("*.ads.example.com"),
            ["ads.example.com"],
        )

    def test_parses_dnsmasq_address(self):
        self.assertEqual(
            parse_source_line(
                "address=/ads.example.com/0.0.0.0"
            ),
            ["ads.example.com"],
        )

    def test_parses_dnsmasq_server(self):
        self.assertEqual(
            parse_source_line(
                "server=/ads.example.com/"
            ),
            ["ads.example.com"],
        )

    def test_parses_dnsmasq_blocking_target(self):
        self.assertEqual(
            parse_source_line(
                "address=/ads.example.com/#"
            ),
            ["ads.example.com"],
        )


class TestBlocklistOptimization(unittest.TestCase):

    def test_parent_block_covers_subdomains(self):
        result = optimize_blocklist(
            {"example.com", "api.example.com"},
            set(),
        )

        self.assertEqual(result, {"example.com"})

    def test_allowlisted_subdomain_is_not_added_to_blocklist(self):
        result = optimize_blocklist(
            {"example.com"},
            {"api.example.com"},
        )

        self.assertEqual(result, {"example.com"})

    def test_more_specific_allowlist_wins(self):
        result = optimize_blocklist(
            {"example.com", "api.example.com"},
            {"api.example.com"},
        )

        self.assertEqual(result, {"example.com"})

    def test_more_specific_block_inside_exception_survives(self):
        result = optimize_blocklist(
            {"example.com", "private.api.example.com"},
            {"api.example.com"},
        )

        self.assertEqual(
            result,
            {"example.com", "private.api.example.com"},
        )

    def test_more_specific_external_block_overrides_parent_exception(self):
        result = optimize_blocklist(
            {"example.com", "v2.api.example.com"},
            {"api.example.com"},
        )

        self.assertEqual(
            result,
            {"example.com", "v2.api.example.com"},
        )

    def test_allowlist_wins_for_identical_external_domain(self):
        result = optimize_blocklist(
            {"ads.example.com"},
            {"ads.example.com"},
        )

        self.assertEqual(result, set())

    def test_custom_block_is_included(self):
        result = optimize_blocklist(
            set(),
            set(),
            {"ads.example.com"},
        )

        self.assertEqual(result, {"ads.example.com"})

    def test_custom_block_overrides_parent_allowlist(self):
        result = optimize_blocklist(
            set(),
            {"example.com"},
            {"private.example.com"},
        )

        self.assertEqual(
            result,
            {"private.example.com"},
        )

    def test_custom_block_and_allowlist_conflict(self):
        with self.assertRaises(ValueError):
            optimize_blocklist(
                set(),
                {"ads.example.com"},
                {"ads.example.com"},
            )

    def test_custom_block_and_external_block_can_coexist(self):
        result = optimize_blocklist(
            {"ads.example.com"},
            set(),
            {"ads.example.com"},
        )

        self.assertEqual(result, {"ads.example.com"})

    def test_more_specific_external_block_overrides_custom_parent_allow(self):
        result = optimize_blocklist(
            {"private.api.example.com"},
            {"api.example.com"},
            set(),
        )

        self.assertEqual(
            result,
            {"private.api.example.com"},
        )


if __name__ == "__main__":
    unittest.main()
