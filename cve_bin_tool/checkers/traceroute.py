# Copyright (C) 2023 Orange
# SPDX-License-Identifier: GPL-3.0-or-later


"""
CVE checker for traceroute

https://www.cvedetails.com/product/163596/BUC-Traceroute.html?vendor_id=33432

"""
from __future__ import annotations

from cve_bin_tool.checkers import Checker


class TracerouteChecker(Checker):
    CONTAINS_PATTERNS: list[str] = []
    FILENAME_PATTERNS: list[str] = []
    VERSION_PATTERNS = [
        r"Modern traceroute for Linux, version ([0-9]+\.[0-9]+\.[0-9]+)"
    ]
    VENDOR_PRODUCT = [("buc", "traceroute")]
