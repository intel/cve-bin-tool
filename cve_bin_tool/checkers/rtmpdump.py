# Copyright (C) 2023 Orange
# SPDX-License-Identifier: GPL-3.0-or-later


"""
CVE checker for rtmpdump

https://www.cvedetails.com/product/37077/Rtmpdump-Project-Rtmpdump.html?vendor_id=16341

"""
from __future__ import annotations

from cve_bin_tool.checkers import Checker


class RtmpdumpChecker(Checker):
    CONTAINS_PATTERNS: list[str] = []
    FILENAME_PATTERNS: list[str] = []
    VERSION_PATTERNS = [r"v([0-9]+\.[0-9]+)\r?\nRTMP"]
    VENDOR_PRODUCT = [("rtmpdump_project", "rtmpdump")]
