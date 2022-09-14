# Copyright (C) 2021 Anthony Harrison
# SPDX-License-Identifier: GPL-3.0-or-later

import pytest

from cve_bin_tool.cve_scanner import CVEScanner
from cve_bin_tool.util import ProductInfo


class TestCVEScanner:
    @pytest.mark.parametrize(
        "version, expected_result",
        (
            ("1.1.0f", "1.1.0.5"),
            ("1.1.0", "1.1.0"),
        ),
    )
    def test_openssl_convert(self, version: str, expected_result: str):
        scanner = CVEScanner()
        assert scanner.openssl_convert(version) == expected_result

    @pytest.mark.parametrize(
        "product, expected_result, between_result",
        (
            (ProductInfo(vendor="", product="glibc", version="2.11.1"), "2.11.1", ""),
            (
                ProductInfo(vendor="", product="glibc", version="2.11.1_pre1"),
                "2.11.1",
                "",
            ),
            (
                ProductInfo(vendor="", product="openssl", version="1.1.0h"),
                "1.1.0h",
                "1.1.0.7",
            ),
            (
                ProductInfo(vendor="", product="openssl", version="1.1.0h_kali2"),
                "1.1.0h",
                "1.1.0.7",
            ),
            (ProductInfo(vendor="", product="openssl", version=""), "", ""),
            (ProductInfo(vendor="", product="php", version="2:7.4"), "7.4", ""),
            (ProductInfo(vendor="", product="php", version="2:7.4_deb0"), "7.4", ""),
        ),
    )
    def test_canonical_convert(
        self, product: ProductInfo, expected_result: str, between_result: str
    ):
        scanner = CVEScanner()
        res1, res2 = scanner.canonical_convert(product)
        assert str(res1) == expected_result
        assert str(res2) == between_result
