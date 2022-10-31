# Copyright (C) 2022 Orange
# SPDX-License-Identifier: GPL-3.0-or-later


"""
CVE checker for nmap

https://www.cvedetails.com/product/26385/Nmap-Nmap.html?vendor_id=12932

"""
from __future__ import annotations

from cve_bin_tool.checkers import Checker


class NmapChecker(Checker):
    CONTAINS_PATTERNS: list[str] = []
    FILENAME_PATTERNS: list[str] = []
    VERSION_PATTERNS = [r"([0-9]+\.[0-9]+)\r?\nNmap"]
    VENDOR_PRODUCT = [("nmap", "nmap")]
