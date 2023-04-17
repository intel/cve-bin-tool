# Copyright (C) 2022 Orange
# SPDX-License-Identifier: GPL-3.0-or-later


"""
CVE checker for janus

https://www.cvedetails.com/product/82836/Meetecho-Janus.html?vendor_id=23192

"""
from __future__ import annotations

from cve_bin_tool.checkers import Checker


class JanusChecker(Checker):
    CONTAINS_PATTERNS: list[str] = []
    FILENAME_PATTERNS: list[str] = []
    VERSION_PATTERNS = [
        r"not-a-git-repo\r?\n([0-9]+\.[0-9]+\.[0-9]+)\r?\njanus",
        r"janus[a-z_]*\r?\n([0-9]+\.[0-9]+\.[0-9]+)",
    ]
    VENDOR_PRODUCT = [("meetecho", "janus")]
