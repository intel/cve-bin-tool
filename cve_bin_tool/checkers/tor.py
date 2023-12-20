# Copyright (C) 2022 Orange
# SPDX-License-Identifier: GPL-3.0-or-later

"""
CVE checker for tor

https://www.cvedetails.com/product/5516/TOR-TOR.html?vendor_id=3132
https://www.cvedetails.com/product/23219/Torproject-TOR.html?vendor_id=12287
https://www.cvedetails.com/product/39020/Debian-TOR.html?vendor_id=23
https://www.cvedetails.com/product/67243/Tor-Project-TOR.html?vendor_id=21651

"""
from __future__ import annotations

from cve_bin_tool.checkers import Checker


class TorChecker(Checker):
    CONTAINS_PATTERNS: list[str] = []
    FILENAME_PATTERNS: list[str] = []
    VERSION_PATTERNS = [r"on Tor ([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)"]
    VENDOR_PRODUCT = [
        ("debian", "tor"),
        ("tor", "tor"),
        ("torproject", "tor"),
        ("tor_project", "tor"),
    ]
