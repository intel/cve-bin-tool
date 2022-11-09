# Copyright (C) 2022 Orange
# SPDX-License-Identifier: GPL-3.0-or-later


"""
CVE checker for quagga

https://www.cvedetails.com/product/20622/Quagga-Quagga.html?vendor_id=1853

"""
from __future__ import annotations

from cve_bin_tool.checkers import Checker


class QuaggaChecker(Checker):
    CONTAINS_PATTERNS: list[str] = []
    FILENAME_PATTERNS: list[str] = []
    VERSION_PATTERNS = [r"Quagga \(version ([0-9]+\.[0-9]+\.[0-9]+)"]
    VENDOR_PRODUCT = [("quagga", "quagga")]
