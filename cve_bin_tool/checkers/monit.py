# Copyright (C) 2023 Orange
# SPDX-License-Identifier: GPL-3.0-or-later


"""
CVE checker for monit

https://www.cvedetails.com/product/3156/Tildeslash-Monit.html?vendor_id=1848
https://www.cvedetails.com/product/61321/Mmonit-Monit.html?vendor_id=14182

"""
from __future__ import annotations

from cve_bin_tool.checkers import Checker


class MonitChecker(Checker):
    CONTAINS_PATTERNS: list[str] = []
    FILENAME_PATTERNS: list[str] = []
    VERSION_PATTERNS = [r"monit ([0-9]+\.[0-9]+\.[0-9]+)"]
    VENDOR_PRODUCT = [("mmonit", "monit"), ("tildeslash", "monit")]
