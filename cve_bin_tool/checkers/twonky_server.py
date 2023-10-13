# Copyright (C) 2023 Orange
# SPDX-License-Identifier: GPL-3.0-or-later


"""
CVE checker for twonky_server

https://www.cvedetails.com/product/70996/Lynxtechnology-Twonky-Server.html?vendor_id=21991

"""
from __future__ import annotations

from cve_bin_tool.checkers import Checker


class TwonkyServerChecker(Checker):
    CONTAINS_PATTERNS: list[str] = []
    FILENAME_PATTERNS: list[str] = []
    VERSION_PATTERNS = [r"Product Name:Twonky, Version:([0-9]+\.[0-9]+\.[0-9]+)"]
    VENDOR_PRODUCT = [("lynxtechnology", "twonky_server")]
