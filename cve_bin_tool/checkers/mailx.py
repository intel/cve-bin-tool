# Copyright (C) 2022 Orange
# SPDX-License-Identifier: GPL-3.0-or-later


"""
CVE checker for mailx

https://www.cvedetails.com/product/30666/Heirloom-Mailx.html?vendor_id=15053

"""
from __future__ import annotations

from cve_bin_tool.checkers import Checker


class MailxChecker(Checker):
    CONTAINS_PATTERNS: list[str] = []
    FILENAME_PATTERNS: list[str] = []
    VERSION_PATTERNS = [r"mailx ([0-9]+\.[0-9]+)"]
    VENDOR_PRODUCT = [("heirloom", "mailx")]
