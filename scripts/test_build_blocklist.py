import unittest

import build_blocklist as builder


class TestNormalizeDomain(unittest.TestCase):

    def test_normalizes_case_and_trailing_dot(self):
        self.assertEqual(
            builder.normalize_domain("Ads.Example.COM."),
            "ads.example.com",
        )

    def test_rejects_ipv4(self):
        self.assertIsNone(
            builder.normalize_domain("192.168.1.1")
        )

    def test_rejects_ipv6(self):
        self.assertIsNone(
            builder.normalize_domain("2001:db8::1")
        )

    def test_rejects_invalid_domain(self):
        invalid_domains = [
            "",
            "localhost",
            "example",
            "-invalid.example",
            "invalid-.example",
            "two..labels.example",
            "domain/path.example",
            "domain:8080.example",
        ]

        for domain in invalid_domains:
            with self.subTest(domain=domain):
                self.assertIsNone(
                    builder.normalize_domain(domain)
                )

    def test_rejects_ignored_domains(self):
        for domain in (
            "example.com",
            "example.net",
            "example.org",
        ):
            with self.subTest(domain=domain):
                self.assertIsNone(
                    builder.normalize_domain(domain)
                )

    def test_accepts_valid_subdomain(self):
        self.assertEqual(
            builder.normalize_domain("api.example.com"),
            "api.example.com",
        )


class TestSourceParsing(unittest.TestCase):

    def test_parses_hosts_entry(self):
        self.assertEqual(
            builder.parse_source_line(
                "0.0.0.0 ads.example.com"
            ),
            ["ads.example.com"],
        )

    def test_parses_hosts_aliases(self):
        self.assertEqual(
            builder.parse_source_line(
                "127.0.0.1 ads.example.com tracker.example.net"
            ),
            ["ads.example.com", "tracker.example.net"],
        )

    def test_ignores_hosts_inline_comment(self):
        self.assertEqual(
            builder.parse_source_line(
                "0.0.0.0 ads.example.com # unwanted tracker"
            ),
            ["ads.example.com"],
        )

    def test_parses_dnsmasq_address(self):
        self.assertEqual(
            builder.parse_source_line(
                "address=/ads.example.com/0.0.0.0"
            ),
            ["ads.example.com"],
        )

    def test_parses_dnsmasq_server(self):
        self.assertEqual(
            builder.parse_source_line(
                "server=/ads.example.com/"
            ),
            ["ads.example.com"],
        )

    def test_parses_domain_wildcard(self):
        self.assertEqual(
            builder.parse_source_line("*.ads.example.com"),
            ["ads.example.com"],
        )

    def test_parses_adblock_domain_rule(self):
        self.assertEqual(
            builder.parse_source_line(
                "||ads.example.com^$third-party"
            ),
            ["ads.example.com"],
        )

    def test_ignores_adblock_exception(self):
        self.assertEqual(
            builder.parse_source_line(
                "@@||safe.example.com^"
            ),
            [],
        )

    def test_ignores_full_line_comments(self):
        self.assertEqual(
            builder.parse_source_line("! comment"),
            [],
        )


class TestBlocklistOptimization(unittest.TestCase):

    def test_parent_block_covers_subdomains(self):
        result = builder.optimize_blocklist(
            {
                "example.com",
                "www.example.com",
                "mail.example.com",
            },
            set(),
        )

        self.assertEqual(result, {"example.com"})

    def test_allowlisted_subdomain_is_not_added_to_blocklist(self):
        result = builder.optimize_blocklist(
            {
                "example.com",
                "www.example.com",
                "api.example.com",
                "other.example.com",
            },
            {"api.example.com"},
        )

        self.assertEqual(result, {"example.com"})

    def test_allowlist_exception_covers_its_subdomains(self):
        result = builder.optimize_blocklist(
            {
                "example.com",
                "api.example.com",
                "v2.api.example.com",
            },
            {"api.example.com"},
        )

        self.assertEqual(result, {"example.com"})

    def test_more_specific_block_inside_exception_survives(self):
        result = builder.optimize_blocklist(
            {
                "example.com",
                "api.example.com",
                "private.api.example.com",
            },
            {"api.example.com"},
        )

        self.assertEqual(
            result,
            {
                "example.com",
                "private.api.example.com",
            },
        )

    def test_allowlist_wins_for_identical_domain(self):
        result = builder.optimize_blocklist(
            {"example.com"},
            {"example.com"},
        )

        self.assertEqual(result, set())

    def test_more_specific_allowlist_wins(self):
        result = builder.optimize_blocklist(
            {
                "example.com",
                "private.example.com",
            },
            {"private.example.com"},
        )

        self.assertEqual(result, {"example.com"})


if __name__ == "__main__":
    unittest.main(verbosity=2)
