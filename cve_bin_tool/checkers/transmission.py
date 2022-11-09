# Copyright (C) 2022 Orange
# SPDX-License-Identifier: GPL-3.0-or-later


"""
CVE checker for transmission

https://www.cvedetails.com/product/17422/Transmissionbt-Transmission.html?vendor_id=9749

"""
from __future__ import annotations

from cve_bin_tool.checkers import Checker


class TransmissionChecker(Checker):
    CONTAINS_PATTERNS: list[str] = []
    FILENAME_PATTERNS: list[str] = []
    VERSION_PATTERNS = [r"Transmission ([0-9]+\.[0-9]+)"]
    VENDOR_PRODUCT = [("transmissionbt", "transmission")]
