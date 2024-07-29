# Copyright (C) 2022 Orange
# SPDX-License-Identifier: GPL-3.0-or-later


"""
CVE checker for gdb

https://www.cvedetails.com/product/5321/GNU-GDB.html?vendor_id=72

"""
from __future__ import annotations

from cve_bin_tool.checkers import Checker


class GdbChecker(Checker):
    CONTAINS_PATTERNS: list[str] = []
    FILENAME_PATTERNS: list[str] = []
    VERSION_PATTERNS = [
        r"gdb-([0-9]+\.[0-9]+\.?[0-9]*)",
        r"\r?\n([0-9]+\.[0-9]+\.?[0-9]*)\r?\n[A-Za-z0-9<>()!,_=|'`+*&^{} \\\.\-\"\r\n\t]*GDB ",
    ]
    VENDOR_PRODUCT = [("gnu", "gdb")]
