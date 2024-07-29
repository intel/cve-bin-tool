# Copyright (C) 2022 Orange
# SPDX-License-Identifier: GPL-3.0-or-later


"""
CVE checker for darkhttpd

https://www.cvedetails.com/product/112161/Darkhttpd-Project-Darkhttpd.html?vendor_id=26797
https://www.cvedetails.com/product/168196/Unix4lyfe-Darkhttpd.html?vendor_id=34424

Note: darkhttpd is not provided on debian and openWRT. Tests use fedora packages only

"""
from __future__ import annotations

from cve_bin_tool.checkers import Checker


class DarkhttpdChecker(Checker):
    CONTAINS_PATTERNS: list[str] = []
    FILENAME_PATTERNS: list[str] = []
    VERSION_PATTERNS = [r"darkhttpd/([0-9]+\.[0-9]+)"]
    VENDOR_PRODUCT = [("darkhttpd_project", "darkhttpd"), ("unix4lyfe", "darkhttpd")]
