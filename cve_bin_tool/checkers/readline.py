# Copyright (C) 2023 Orange
# SPDX-License-Identifier: GPL-3.0-or-later


"""
CVE checker for readline

https://www.cvedetails.com/product/28345/GNU-Readline.html?vendor_id=72

"""
from __future__ import annotations

from cve_bin_tool.checkers import Checker


class ReadlineChecker(Checker):
    CONTAINS_PATTERNS: list[str] = []
    FILENAME_PATTERNS: list[str] = []
    VERSION_PATTERNS = [
        r"([0-9]+\.[0-9]+)\r?\n_\*\\AaIiCcDdPpYyRrSsXx~",
        r"libreadline.so.([0-9]+\.[0-9]+)",
    ]
    VENDOR_PRODUCT = [("gnu", "readline")]
