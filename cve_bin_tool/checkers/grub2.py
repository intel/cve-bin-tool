# Copyright (C) 2022 Orange
# SPDX-License-Identifier: GPL-3.0-or-later


"""
CVE checker for grub2

https://www.cvedetails.com/product/27576/GNU-Grub.html?vendor_id=72
https://www.cvedetails.com/product/32736/GNU-Grub2.html?vendor_id=72

"""
from __future__ import annotations

from cve_bin_tool.checkers import Checker


class Grub2Checker(Checker):
    CONTAINS_PATTERNS: list[str] = []
    FILENAME_PATTERNS: list[str] = []
    VERSION_PATTERNS = [
        r"GRUB2 ([0-9]+\.[0-9]+)",
        r"GRUB\r?\n([0-9]+\.[0-9]+)",
    ]
    VENDOR_PRODUCT = [("gnu", "grub"), ("gnu", "grub2")]
