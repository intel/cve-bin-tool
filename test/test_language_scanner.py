# Copyright (C) 2021 Anthony Harrison
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import annotations

from pathlib import Path
from test.utils import LONG_TESTS

import pytest

from cve_bin_tool import parsers
from cve_bin_tool.cvedb import CVEDB
from cve_bin_tool.log import LOGGER
from cve_bin_tool.version_scanner import VersionScanner


class TestLanguageScanner:
    """Tests for various language scanners"""

    TEST_FILE_PATH = Path(__file__).parent.resolve() / "language_data"

    JAVASCRIPT_PRODUCTS = [
        "cache",
        "core",
        "http-client",
        "generator",
        "expect",
    ]

    RUST_PRODUCTS = [
        "bumpalo",
        "cranelift-codegen",
        "crossbeam-channel",
        "digest",
        "generic-array",
        "hex",
        "libc",
        "linked-hash-map",
        "lock_api",
        "memoffset",
        "nix",
        "once_cell",
        "openssl",
        "paste",
        "phf",
        "quote",
        "rand_core",
        "regex",
        "serde_cbor",
        "sha2",
        "smallvec",
        "socket2",
        "time",
        "yaml-rust",
    ]

    RUBY_PRODUCTS = [
        "addressable",
        "backburner",
        "builder",
        "crack",
        "curses",
        "dalli",
        "debug",
        "digest",
        "em-http-request",
        "faye",
        "faye-websocket",
        "httpclient",
        "i18n",
        "image_processing",
        "jmespath",
        "json",
        "jwt",
        "loofah",
        "mail",
        "matrix",
        "mini_magick",
        "nokogiri",
        "parallel",
        "pg",
        "puma",
        "rack",
        "rack-protection",
        "rake",
        "rdoc",
        "redcarpet",
        "redis",
        "rexml",
        "rubocop",
        "rubyzip",
        "set",
        "sidekiq",
        "sinatra",
        "sprockets",
        "sqlite3",
        "terser",
        "thin",
        "thor",
        "tzinfo",
        "useragent",
        "webrick",
        "websocket",
        "websocket-extensions",
    ]

    R_PRODUCTS = [
        "cli",
        "clipr",
        "commonmark",
        "crayon",
        "credentials",
        "curl",
        "digest",
        "evaluate",
        "glue",
        "lattice",
        "lifecycle",
        "mime",
        "openssl",
        "ps",
        "xopen",
        "yaml",
        "zip",
    ]

    PYTHON_PRODUCTS = [
        "plotly",
        "zstandard",
        "requests",
        "urllib3",
        "rsa",
        "aiohttp",
        "httplib2",
        "cryptography",
    ]

    GO_PRODUCTS = [
        "json-patch",
        "protobuf",
        "net",
        "term",
        "time",
        "api",
        "yaml",
        "jsonpointer",
        "go",
        "text",
        "appengine",
        "json",
    ]
    PHP_PRODUCTS = [
        "cli",
        "cron",
        "csrf",
        "database",
        "phpunit",
    ]
    PERL_PRODUCTS = ["perl", "warnings", "base"]

    SWIFT_PRODUCTS = ["alliance_web_platform"]

    DART_PRODUCTS = ["dio", "archive"]

    @classmethod
    def setup_class(cls):
        cls.cvedb = CVEDB()
        print("Setting up database.")
        cls.cvedb.get_cvelist_if_stale()
        print("Database setup complete.")

    @pytest.mark.parametrize(
        "filename, product_list",
        (
            (
                (str(TEST_FILE_PATH / "pom.xml")),
                ["jmeter", "hamcrest", "slf4j-simple", "slf4j-api"],
            ),
        ),
    )
    def test_java_package(self, filename: str, product_list: set[str]) -> None:
        """Test against a valid pom.xml file for Java packages"""
        scanner = VersionScanner()
        scanner.file_stack.append(filename)
        # check list of product_names
        for product in scanner.scan_file(filename):
            if product:
                product_info, file_path = product
        assert product_info.product in product_list
        assert file_path == filename

    @pytest.mark.parametrize(
        "filename", ((str(TEST_FILE_PATH / "fail-package-lock.json")),)
    )
    def test_javascript_package_none_found(self, filename: str) -> None:
        """Test an invalid package-lock.json file"""
        scanner = VersionScanner()
        scanner.file_stack.append(filename)
        product = None
        # Not expecting any product to match with a vendor in the database
        for product in scanner.scan_file(filename):
            pass
        assert product is not None

    @pytest.mark.parametrize(
        "filename",
        [
            (str(TEST_FILE_PATH / "fail_pom.xml")),
        ],
    )
    def test_language_package_none_found(self, filename: str) -> None:
        """Test for cases where no products match a vendor in the database"""
        scanner = VersionScanner()
        scanner.file_stack.append(filename)
        product = None
        # Not expecting any product to match with a vendor in the database
        for product in scanner.scan_file(filename):
            pass
        assert product is None

    @pytest.mark.parametrize(
        "filename,parser_class,products,namespace",
        [
            pytest.param(
                str(TEST_FILE_PATH / "renv.lock"),
                parsers.r.RParser,
                R_PRODUCTS,
                "cran",
                marks=[
                    pytest.mark.skipif(
                        not LONG_TESTS(),
                        reason="Test reduction in short tests",
                    )
                ],
            ),
            pytest.param(
                str(TEST_FILE_PATH / "Cargo.lock"),
                parsers.rust.RustParser,
                RUST_PRODUCTS,
                "cargo",
                marks=[
                    pytest.mark.skipif(
                        not LONG_TESTS(),
                        reason="Test reduction in short tests",
                    )
                ],
            ),
            pytest.param(
                str(TEST_FILE_PATH / "Gemfile.lock"),
                parsers.ruby.RubyParser,
                RUBY_PRODUCTS,
                "gem",
                marks=[
                    pytest.mark.skipif(
                        not LONG_TESTS(),
                        reason="Test reduction in short tests",
                    )
                ],
            ),
            pytest.param(
                str(TEST_FILE_PATH / "requirements.txt"),
                parsers.python.PythonParser,
                PYTHON_PRODUCTS,
                "pypi",
                marks=[
                    pytest.mark.skipif(
                        not LONG_TESTS(),
                        reason="Test reduction in short tests",
                    )
                ],
            ),
            pytest.param(
                str(TEST_FILE_PATH / "package-lock.json"),
                parsers.javascript.JavascriptParser,
                JAVASCRIPT_PRODUCTS,
                "npm",
                marks=[
                    pytest.mark.skipif(
                        not LONG_TESTS(),
                        reason="Test reduction in short tests",
                    )
                ],
            ),
            pytest.param(
                str(TEST_FILE_PATH / "go.mod"),
                parsers.go.GoParser,
                GO_PRODUCTS,
                "golang",
                marks=[
                    pytest.mark.skipif(
                        not LONG_TESTS(),
                        reason="Test reduction in short tests",
                    )
                ],
            ),
            pytest.param(
                str(TEST_FILE_PATH / "Package.resolved"),
                parsers.swift.SwiftParser,
                SWIFT_PRODUCTS,
                "swift",
                marks=[
                    pytest.mark.skipif(
                        not LONG_TESTS(),
                        reason="Test reduction in short tests",
                    )
                ],
            ),
            pytest.param(
                str(TEST_FILE_PATH / "composer.lock"),
                parsers.php.PhpParser,
                PHP_PRODUCTS,
                "composer",
                marks=[
                    pytest.mark.skipif(
                        not LONG_TESTS(),
                        reason="Test reduction in short tests",
                    )
                ],
            ),
            pytest.param(
                str(TEST_FILE_PATH / "cpanfile"),
                parsers.perl.PerlParser,
                PERL_PRODUCTS,
                "cpan",
                marks=[
                    pytest.mark.skipif(
                        not LONG_TESTS(),
                        reason="Test reduction in short tests",
                    )
                ],
            ),
            pytest.param(
                str(TEST_FILE_PATH / "pubspec.lock"),
                parsers.dart.DartParser,
                DART_PRODUCTS,
                "pub",
                marks=[
                    pytest.mark.skipif(
                        not LONG_TESTS(),
                        reason="Test reduction in short tests",
                    )
                ],
            ),
        ],
    )
    def test_language_package(
        self, filename: str, parser_class, products: set[str], namespace
    ) -> None:
        """Test valid language product list files"""
        instance = parser_class(CVEDB(), LOGGER)

        for p in products:
            purl = instance.generate_purl(p).to_string()
            expected = "pkg:" + namespace + "/" + p
            assert purl == expected

        scanner = VersionScanner()
        scanner.file_stack.append(filename)
        found_product = []
        for product in scanner.scan_file(filename):
            if product:
                product_info, file_path = product
                if product_info.product not in found_product:
                    found_product.append(product_info.product)
        # assert all(x in products for x in found_product)
        # expanded out to make missing products easier to spot
        for p in products:
            assert p in found_product
        assert file_path == filename

    @pytest.mark.parametrize("filename", ((str(TEST_FILE_PATH / "PKG-INFO")),))
    def test_python_package(self, filename: str) -> None:
        """Test against python's PKG-INFO metadata file"""
        scanner = VersionScanner()
        scanner.file_stack.append(filename)
        for product in scanner.scan_file(filename):
            if product:
                product_info, file_path = product
                assert product_info[1] == "zstandard"
                assert product_info[2] == "0.18.0"
                assert product_info[3] == filename
        assert file_path == filename
