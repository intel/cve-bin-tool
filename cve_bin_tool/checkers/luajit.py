# Copyright (C) 2022 Orange
# SPDX-License-Identifier: GPL-3.0-or-later


"""
CVE checker for luajit

https://www.cvedetails.com/vulnerability-list/vendor_id-22486/Luajit.html

"""
from __future__ import annotations

from cve_bin_tool.checkers import Checker


class LuajitChecker(Checker):
    CONTAINS_PATTERNS: list[str] = []
    FILENAME_PATTERNS = [r"lua", r"luajit"]
    VERSION_PATTERNS = [r"LuaJIT ([0-9]+\.[0-9]+\.[0-9]+)[a-z0-9\-]*(?: |\r?\njit)"]
    VENDOR_PRODUCT = [("luajit", "luajit")]
