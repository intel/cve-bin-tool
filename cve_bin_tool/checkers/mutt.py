# Copyright (C) 2022 Orange
# SPDX-License-Identifier: GPL-3.0-or-later


"""
CVE checker for mutt

https://www.cvedetails.com/product/274/Mutt-Mutt.html?vendor_id=158

"""
from __future__ import annotations

from cve_bin_tool.checkers import Checker


class MuttChecker(Checker):
    CONTAINS_PATTERNS: list[str] = []
    FILENAME_PATTERNS: list[str] = []
    VERSION_PATTERNS = [
        r"muttrc-([0-9]+\.[0-9]+\.[0-9]+)",
        r"([0-9]+\.[0-9]+\.[0-9]+)\r?\nMutt",
        r"Mutt %s \(%s\)\r?\n([0-9]+\.[0-9]+\.[0-9]+)",
    ]
    VENDOR_PRODUCT = [("mutt", "mutt")]
