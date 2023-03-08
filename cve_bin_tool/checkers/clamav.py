# Copyright (C) 2022 Orange
# SPDX-License-Identifier: GPL-3.0-or-later


"""
CVE checker for clamav

https://www.cvedetails.com/product/3173/Clam-Anti-virus-Clamav.html?vendor_id=1857
https://www.cvedetails.com/product/15657/Clamav-Clamav.html?vendor_id=8871
https://www.cvedetails.com/product/17215/Clamavs-Clamav.html?vendor_id=9637

"""
from __future__ import annotations

from cve_bin_tool.checkers import Checker


class ClamavChecker(Checker):
    CONTAINS_PATTERNS: list[str] = []
    FILENAME_PATTERNS: list[str] = []
    VERSION_PATTERNS = [
        r"clamav-([0-9]+\.[0-9]+\.[0-9]+)",
        r"([0-9]+\.[0-9]+\.[0-9]+)\r?\nUnable to allocate memory for db directory...\r?\n%s/daily.cvd\r?\n%s/daily.cld\r?\nClamAV %s",
    ]
    VENDOR_PRODUCT = [
        ("clam_anti-virus", "clamav"),
        ("clamav", "clamav"),
        ("clamavs", "clamav"),
    ]
