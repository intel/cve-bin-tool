# Copyright (C) 2022 Orange
# SPDX-License-Identifier: GPL-3.0-or-later


"""
CVE checker for thttpd

https://www.cvedetails.com/product/899/Acme-Labs-Thttpd.html?vendor_id=521
https://www.cvedetails.com/product/18644/Acme-Thttpd.html?vendor_id=10442

Note: thttpd is not provided by debian or openWRT. Tests provided are fedora-only.

"""
from __future__ import annotations

from cve_bin_tool.checkers import Checker


class ThttpdChecker(Checker):
    CONTAINS_PATTERNS: list[str] = []
    FILENAME_PATTERNS: list[str] = []
    VERSION_PATTERNS = [r"thttpd/([0-9]+\.[0-9]+)"]
    VENDOR_PRODUCT = [("acme_labs", "thttpd"), ("acme", "thttpd")]
