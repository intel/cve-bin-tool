# Copyright (C) 2021 Anthony Harrison
# SPDX-License-Identifier: GPL-3.0-or-later

from pathlib import Path

import pytest

from cve_bin_tool.cvedb import CVEDB
from cve_bin_tool.util import ProductInfo
from cve_bin_tool.version_scanner import VersionScanner


class TestLanguageScanner:
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
        "commonmark",
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

    SWIFT_PRODUCTS = ["alliance_web_platform"]

    @classmethod
    def setup_class(cls):
        cls.cvedb = CVEDB()
        print("Setting up database.")
        cls.cvedb.get_cvelist_if_stale()
        print("Database setup complete.")

    @pytest.mark.parametrize(
        "filename, product_name",
        (((str(TEST_FILE_PATH / "pom.xml")), "commons_io"),),
    )
    def test_java_package(self, filename: str, product_name: str) -> None:
        scanner = VersionScanner()
        scanner.file_stack.append(filename)
        # Only expecting to get one product with a vendor in the database
        for product in scanner.scan_file(filename):
            if product:
                product_info, file_path = product
        assert product_info.product == product_name
        assert file_path == filename

    @pytest.mark.parametrize(
        "filename", ((str(TEST_FILE_PATH / "fail-package-lock.json")),)
    )
    def test_javascript_package_none_found(self, filename: str) -> None:
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
            (str(TEST_FILE_PATH / "FAIL-PKG-INFO")),
            (str(TEST_FILE_PATH / "fail_pom.xml")),
        ],
    )
    def test_language_package_none_found(self, filename: str) -> None:
        scanner = VersionScanner()
        scanner.file_stack.append(filename)
        product = None
        # Not expecting any product to match with a vendor in the database
        for product in scanner.scan_file(filename):
            pass
        assert product is None

    @pytest.mark.parametrize(
        "filename,products",
        [
            (str(TEST_FILE_PATH / "renv.lock"), R_PRODUCTS),
            (str(TEST_FILE_PATH / "Cargo.lock"), RUST_PRODUCTS),
            (str(TEST_FILE_PATH / "Gemfile.lock"), RUBY_PRODUCTS),
            (str(TEST_FILE_PATH / "requirements.txt"), PYTHON_PRODUCTS),
            (str(TEST_FILE_PATH / "package-lock.json"), JAVASCRIPT_PRODUCTS),
            (str(TEST_FILE_PATH / "go.mod"), GO_PRODUCTS),
            (str(TEST_FILE_PATH / "Package.resolved"), SWIFT_PRODUCTS),
        ],
    )
    def test_language_package(self, filename: str, products) -> None:
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
        scanner = VersionScanner()
        scanner.file_stack.append(filename)
        for product in scanner.scan_file(filename):
            if product:
                product_info, file_path = product
        assert product_info == ProductInfo("facebook", "zstandard", "0.18.0")
        assert file_path == filename
