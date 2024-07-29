# Copyright (C) 2023 Orange
# SPDX-License-Identifier: GPL-3.0-or-later


"""
CVE checker for mbedtls

https://www.cvedetails.com/product/32568/ARM-Mbed-Tls.html?vendor_id=15698

"""
from __future__ import annotations

from cve_bin_tool.checkers import Checker


class MbedtlsChecker(Checker):
    CONTAINS_PATTERNS: list[str] = []
    FILENAME_PATTERNS: list[str] = []
    VERSION_PATTERNS = [r"[m|M]bed TLS ([0-9]+\.[0-9]+\.[0-9]+)"]
    VENDOR_PRODUCT = [("arm", "mbed_tls")]
