# Copyright (C) 2021 Anthony Harrison
# SPDX-License-Identifier: GPL-3.0-or-later

import os

import pytest

from cve_bin_tool.version_scanner import VersionScanner


class TestLanguageScanner:
    TEST_FILE_PATH = os.path.join(
        os.path.abspath(os.path.dirname(__file__)), "language_data"
    )
    JAVASCRIPT_PRODUCTS = [
        "cache",
        "core",
        "http-client",
        "generator",
        "expect",
        "yargs-parser",
    ]

    @pytest.mark.parametrize(
        "filename, product_name",
        (((os.path.join(TEST_FILE_PATH, "pom.xml")), "commons_io"),),
    )
    def test_java_package(self, filename: str, product_name: str) -> None:
        scanner = VersionScanner()
        scanner.file_stack.append(filename)
        # Only expecting to get one product with a vendor in the database
        for product in scanner.run_java_checker(filename):
            if product:
                product_info, file_path = product
        assert product_info.product == product_name
        assert file_path == filename

    @pytest.mark.parametrize(
        "filename", ((os.path.join(TEST_FILE_PATH, "pom_fail.xml")),)
    )
    def test_java_package_none_found(self, filename: str) -> None:
        scanner = VersionScanner()
        scanner.file_stack.append(filename)
        product = None
        # Not expecting any product to match with a vendor in the database
        for product in scanner.run_java_checker(filename):
            pass
        assert product is None

    @pytest.mark.parametrize(
        "filename", ((os.path.join(TEST_FILE_PATH, "package-lock1.json")),)
    )
    def test_javascript_package(self, filename: str) -> None:
        scanner = VersionScanner()
        scanner.file_stack.append(filename)
        found_product = []
        for product in scanner.run_js_checker(filename):
            if product:
                product_info, file_path = product
                if product_info.product not in found_product:
                    found_product.append(product_info.product)
        assert found_product == self.JAVASCRIPT_PRODUCTS
        assert file_path == filename

    @pytest.mark.parametrize(
        "filename", ((os.path.join(TEST_FILE_PATH, "package.json")),)
    )
    def test_javascript_package_none_found(self, filename: str) -> None:
        scanner = VersionScanner()
        scanner.file_stack.append(filename)
        product = None
        # Not expecting any product to match with a vendor in the database
        for product in scanner.run_js_checker(filename):
            pass
        assert product is not None
