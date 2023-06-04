# Copyright (C) 2022 Orange
# SPDX-License-Identifier: GPL-3.0-or-later


"""
CVE checker for proftpd

https://www.cvedetails.com/product/353/Proftpd-Project-Proftpd.html?vendor_id=204
https://www.cvedetails.com/product/16873/Proftpd-Proftpd.html?vendor_id=9520

"""
from __future__ import annotations

from cve_bin_tool.checkers import Checker


class ProftpdChecker(Checker):
    CONTAINS_PATTERNS: list[str] = []
    FILENAME_PATTERNS: list[str] = []
    VERSION_PATTERNS = [r"ProFTPD ([0-9]+\.[0-9]+\.[0-9a-z]+) "]
    VENDOR_PRODUCT = [("proftpd_project", "proftpd"), ("proftpd", "proftpd")]
