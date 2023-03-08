# Copyright (C) 2022 Orange
# SPDX-License-Identifier: GPL-3.0-or-later


"""
CVE checker for stunnel

https://www.cvedetails.com/product/1122/Stunnel-Stunnel.html?vendor_id=659

"""
from __future__ import annotations

from cve_bin_tool.checkers import Checker


class StunnelChecker(Checker):
    CONTAINS_PATTERNS: list[str] = []
    FILENAME_PATTERNS: list[str] = []
    VERSION_PATTERNS = [r"stunnel ([0-9]+\.[0-9]+)"]
    VENDOR_PRODUCT = [("stunnel", "stunnel")]
