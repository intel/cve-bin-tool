# Copyright (C) 2022 Orange
# SPDX-License-Identifier: GPL-3.0-or-later


"""
CVE checker for pure-ftpd

https://www.cvedetails.com/product/20682/Pureftpd-Pure-ftpd.html?vendor_id=2152

"""
from __future__ import annotations

from cve_bin_tool.checkers import Checker


class PureFtpdChecker(Checker):
    CONTAINS_PATTERNS: list[str] = []
    FILENAME_PATTERNS: list[str] = []
    VERSION_PATTERNS = [r"Pure-FTPd ([0-9]+\.[0-9]+\.[0-9]+)"]
    VENDOR_PRODUCT = [("pureftpd", "pure-ftpd")]
