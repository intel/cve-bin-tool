# Copyright (C) 2022 Orange
# SPDX-License-Identifier: GPL-3.0-or-later


"""
CVE checker for util-linux

https://www.cvedetails.com/product/1611/Andries-Brouwer-Util-linux.html?vendor_id=940
https://www.cvedetails.com/product/13878/Linux-Util-linux.html?vendor_id=33
https://www.cvedetails.com/product/26887/Kernel-Util-linux.html?vendor_id=7630
https://www.cvedetails.com/product/36039/Util-linux-Project-Util-linux.html?vendor_id=16138

"""
from __future__ import annotations

from cve_bin_tool.checkers import Checker


class UtilLinuxChecker(Checker):
    CONTAINS_PATTERNS: list[str] = []
    FILENAME_PATTERNS: list[str] = []
    VERSION_PATTERNS = [r"util-linux[ -]([0-9]+\.[0-9]+(\.[0-9]+)?)"]
    VENDOR_PRODUCT = [
        ("andries_brouwer", "util-linux"),
        ("kernel", "util-linux"),
        ("linux", "util-linux"),
        ("util-linux_project", "util-linux"),
    ]
