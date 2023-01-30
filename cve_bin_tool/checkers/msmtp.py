# Copyright (C) 2023 Orange
# SPDX-License-Identifier: GPL-3.0-or-later


"""
CVE checker for msmtp

https://www.cvedetails.com/product/18317/Martin-Lambers-Msmtp.html?vendor_id=10257
https://www.cvedetails.com/product/78099/Marlam-Msmtp.html?vendor_id=22638

"""
from __future__ import annotations

from cve_bin_tool.checkers import Checker


class MsmtpChecker(Checker):
    CONTAINS_PATTERNS: list[str] = []
    FILENAME_PATTERNS: list[str] = []
    VERSION_PATTERNS = [
        r"msmtp\r?\n([0-9]+\.[0-9]+\.[0-9]+)",
        r"msmtp\r?\n%s version %s\r?\n([0-9]+\.[0-9]+\.[0-9]+)",
    ]
    VENDOR_PRODUCT = [("marlam", "msmtp"), ("martin_lambers", "msmtp")]
