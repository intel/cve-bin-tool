# Copyright (C) 2023 Orange
# SPDX-License-Identifier: GPL-3.0-or-later


"""
CVE checker for coreutils

https://www.cvedetails.com/product/5075/GNU-Coreutils.html?vendor_id=72

"""
from __future__ import annotations

from cve_bin_tool.checkers import Checker


class CoreutilsChecker(Checker):
    CONTAINS_PATTERNS: list[str] = []
    FILENAME_PATTERNS: list[str] = []
    VERSION_PATTERNS = [
        r"coreutils-([0-9]+\.[0-9]+)",
        r"coreutils[a-zA-Z0-9:%'<>_/=!, \.\-\(\)\r\n]*\r?\n([0-9]+\.[0-9]+)\r?\n",
    ]
    VENDOR_PRODUCT = [("gnu", "coreutils")]
