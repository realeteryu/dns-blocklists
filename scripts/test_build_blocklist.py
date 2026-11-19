import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import msgpack

from build_blocklist import (
    normalize_domain,
    parse_source_line,
    optimize_blocklist,
    load_domain_file,
    load_allowlist,
    load_custom_blocklist,
    load_block_domains,
    validate_outputs,
    write_atomic,
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
        self.assertIsNone(normalize_domain("2001:db8::1"))

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
            parse_source_line("server=/ads.example.com/"),
            ["ads.example.com"],
        )

    def test_parses_dnsmasq_blocking_target(self):
        self.assertEqual(
            parse_source_line("address=/ads.example.com/#"),
            ["ads.example.com"],
        )


class TestDomainFileLoading(unittest.TestCase):

    def test_loads_domains_and_ignores_comments(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "domains.txt"
            path.write_text(
                "# komentarz\n"
                "\n"
                "Ads.Example.PL.\n"
                "tracker.example.net\n",
                encoding="utf-8",
            )

            result = load_domain_file(path)

            self.assertEqual(
                result,
                {
                    "ads.example.pl",
                    "tracker.example.net",
                },
            )

    def test_removes_duplicate_domains(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "domains.txt"
            path.write_text(
                "ads.example.pl\n"
                "ADS.EXAMPLE.PL\n",
                encoding="utf-8",
            )

            self.assertEqual(
                load_domain_file(path),
                {"ads.example.pl"},
            )

    def test_missing_required_file_raises_error(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "missing.txt"

            with self.assertRaises(FileNotFoundError):
                load_domain_file(path)

    def test_missing_optional_file_returns_empty_set(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "missing.txt"

            self.assertEqual(
                load_domain_file(path, required=False),
                set(),
            )

    def test_invalid_domain_reports_line_number(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "domains.txt"
            path.write_text(
                "# komentarz\n"
                "valid.example.pl\n"
                "invalid domain\n",
                encoding="utf-8",
            )

            with self.assertRaisesRegex(ValueError, "linia 3"):
                load_domain_file(path)

    def test_load_allowlist_uses_configured_file(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "allowlist.txt"
            path.write_text(
                "safe.example.pl\n",
                encoding="utf-8",
            )

            with patch("build_blocklist.ALLOWLIST_FILE", path):
                self.assertEqual(
                    load_allowlist(),
                    {"safe.example.pl"},
                )

    def test_load_custom_blocklist_uses_configured_file(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "custom-blocklist.txt"
            path.write_text(
                "mine.example.pl\n",
                encoding="utf-8",
            )

            with patch(
                "build_blocklist.CUSTOM_BLOCKLIST_FILE",
                path,
            ):
                self.assertEqual(
                    load_custom_blocklist(),
                    {"mine.example.pl"},
                )

    def test_missing_custom_blocklist_is_allowed(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "custom-blocklist.txt"

            with patch(
                "build_blocklist.CUSTOM_BLOCKLIST_FILE",
                path,
            ):
                self.assertEqual(
                    load_custom_blocklist(),
                    set(),
                )


class TestBlockDomainLoading(unittest.TestCase):

    def test_loads_and_counts_source_domains(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "combined_raw.txt"
            path.write_text(
                "# komentarz\n"
                "0.0.0.0 ads.example.pl\n"
                "||tracker.example.net^\n"
                "invalid domain\n",
                encoding="utf-8",
            )

            with patch("build_blocklist.RAW_FILE", path):
                domains, stats = load_block_domains()

            self.assertEqual(
                domains,
                {
                    "ads.example.pl",
                    "tracker.example.net",
                },
            )
            self.assertEqual(stats["raw_lines"], 4)
            self.assertEqual(stats["accepted"], 2)
            self.assertEqual(stats["invalid"], 1)
            self.assertEqual(stats["ignored"], 1)

    def test_missing_raw_file_raises_error(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "missing.txt"

            with patch("build_blocklist.RAW_FILE", path):
                with self.assertRaises(FileNotFoundError):
                    load_block_domains()

    def test_empty_raw_file_raises_error(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "combined_raw.txt"
            path.write_text("", encoding="utf-8")

            with patch("build_blocklist.RAW_FILE", path):
                with self.assertRaises(ValueError):
                    load_block_domains()


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


class TestOutputValidation(unittest.TestCase):

    def make_output_data(self, blocklist, allowlist):
        sorted_blocks = sorted(blocklist)
        sorted_allows = sorted(allowlist)

        txt_data = (
            "\n".join(sorted_blocks) + "\n"
        ).encode("utf-8")

        policy_data = msgpack.packb(
            {
                "blocklist": sorted_blocks,
                "allowlist": sorted_allows,
            },
            use_bin_type=True,
        )

        return txt_data, policy_data

    def test_accepts_matching_outputs(self):
        blocklist = {"ads.example.pl"}
        allowlist = {"safe.example.net"}

        txt_data, policy_data = self.make_output_data(
            blocklist,
            allowlist,
        )

        validate_outputs(
            blocklist,
            allowlist,
            txt_data,
            policy_data,
        )

    def test_accepts_matching_combined_policy(self):
        blocklist = {"ads.example.pl"}
        allowlist = {"safe.example.net"}

        txt_data, policy_data = self.make_output_data(
            blocklist,
            allowlist,
        )

        validate_outputs(
            blocklist,
            allowlist,
            txt_data,
            policy_data,
        )

        decoded_policy = msgpack.unpackb(
            policy_data,
            raw=False,
        )

        self.assertEqual(
            decoded_policy,
            {
                "blocklist": ["ads.example.pl"],
                "allowlist": ["safe.example.net"],
            },
        )

    def test_rejects_policy_with_incorrect_structure(self):
        blocklist = {"ads.example.pl"}
        allowlist = {"safe.example.net"}

        txt_data, _ = self.make_output_data(
            blocklist,
            allowlist,
        )

        wrong_policy = msgpack.packb(
            ["ads.example.pl", "safe.example.net"],
            use_bin_type=True,
        )

        with self.assertRaisesRegex(ValueError, "musi być obiektem"):
            validate_outputs(
                blocklist,
                allowlist,
                txt_data,
                wrong_policy,
            )

    def test_rejects_policy_with_missing_list(self):
        blocklist = {"ads.example.pl"}
        allowlist = set()

        txt_data, _ = self.make_output_data(
            blocklist,
            allowlist,
        )

        wrong_policy = msgpack.packb(
            {"blocklist": ["ads.example.pl"]},
            use_bin_type=True,
        )

        with self.assertRaisesRegex(ValueError, "nieprawidłową strukturę"):
            validate_outputs(
                blocklist,
                allowlist,
                txt_data,
                wrong_policy,
            )

    def test_rejects_policy_with_mismatched_domains(self):
        blocklist = {"ads.example.pl"}
        allowlist = {"safe.example.net"}

        txt_data, _ = self.make_output_data(
            blocklist,
            allowlist,
        )

        wrong_policy = msgpack.packb(
            {
                "blocklist": ["wrong.example.pl"],
                "allowlist": ["safe.example.net"],
            },
            use_bin_type=True,
        )

        with self.assertRaisesRegex(ValueError, "Bloklista w polityce"):
            validate_outputs(
                blocklist,
                allowlist,
                txt_data,
                wrong_policy,
            )

    def test_rejects_domain_present_in_both_policy_lists(self):
        blocklist = {"ads.example.pl"}
        allowlist = {"safe.example.net"}

        txt_data, _ = self.make_output_data(
            blocklist,
            allowlist,
        )

        wrong_policy = msgpack.packb(
            {
                "blocklist": ["ads.example.pl"],
                "allowlist": ["ads.example.pl"],
            },
            use_bin_type=True,
        )

        with self.assertRaisesRegex(ValueError, "Polityka zawiera domenę"):
            validate_outputs(
                blocklist,
                allowlist,
                txt_data,
                wrong_policy,
            )

    def test_rejects_incorrect_txt_output(self):
        blocklist = {"ads.example.pl"}
        allowlist = set()

        _, policy_data = self.make_output_data(
            blocklist,
            allowlist,
        )

        with self.assertRaisesRegex(ValueError, "TXT"):
            validate_outputs(
                blocklist,
                allowlist,
                b"wrong.example.pl\n",
                policy_data,
            )

    def test_rejects_domain_present_in_both_outputs(self):
        blocklist = {"ads.example.pl"}
        allowlist = {"ads.example.pl"}

        txt_data, policy_data = self.make_output_data(
            blocklist,
            allowlist,
        )

        with self.assertRaisesRegex(ValueError, "Polityka zawiera domenę w obu listach"):
            validate_outputs(
                blocklist,
                allowlist,
                txt_data,
                policy_data,
            )

    def test_rejects_invalid_domain_in_output(self):
        blocklist = {"invalid domain"}
        allowlist = set()

        txt_data, policy_data = self.make_output_data(
            blocklist,
            allowlist,
        )

        with self.assertRaisesRegex(ValueError, "Nieprawidłowa domena"):
            validate_outputs(
                blocklist,
                allowlist,
                txt_data,
                policy_data,
            )


class TestAtomicWriting(unittest.TestCase):

    def test_writes_file_content(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "output" / "result.bin"
            content = b"test-data"

            write_atomic(path, content)

            self.assertTrue(path.exists())
            self.assertEqual(path.read_bytes(), content)

    def test_replaces_existing_file(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "result.bin"
            path.write_bytes(b"old-data")

            write_atomic(path, b"new-data")

            self.assertEqual(
                path.read_bytes(),
                b"new-data",
            )


if __name__ == "__main__":
    unittest.main()
