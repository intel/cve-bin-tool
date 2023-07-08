# Copyright (C) 2023 Orange
# SPDX-License-Identifier: GPL-3.0-or-later


"""
CVE checker for mini_httpd

https://www.cvedetails.com/product/18643/Acme-Mini-Httpd.html?vendor_id=10442
https://www.cvedetails.com/product/70152/Acme-Mini-httpd.html?vendor_id=10442

"""
from __future__ import annotations

from cve_bin_tool.checkers import Checker


class MiniHttpdChecker(Checker):
    CONTAINS_PATTERNS: list[str] = []
    FILENAME_PATTERNS: list[str] = []
    VERSION_PATTERNS = [r"mini_httpd/([0-9]+\.[0-9]+)"]
    VENDOR_PRODUCT = [("acme", "mini_httpd"), ("acme", "mini-httpd")]
