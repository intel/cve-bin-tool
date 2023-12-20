# Copyright (C) 2023 Orange
# SPDX-License-Identifier: GPL-3.0-or-later


"""
CVE checker for libvpx

https://www.cvedetails.com/product/62243/Webmproject-Libvpx.html?vendor_id=17610

"""
from __future__ import annotations

from cve_bin_tool.checkers import Checker


class LibvpxChecker(Checker):
    CONTAINS_PATTERNS: list[str] = []
    FILENAME_PATTERNS: list[str] = []
    VERSION_PATTERNS = [r"WebM Project VP[8|9] Encoder v([0-9]+\.[0-9]+\.[0-9]+)"]
    VENDOR_PRODUCT = [("webmproject", "libvpx")]
