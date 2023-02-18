# Copyright (C) 2023 Orange
# SPDX-License-Identifier: GPL-3.0-or-later


"""
CVE checker for speex

https://www.cvedetails.com/product/20855/Xiph-Speex.html?vendor_id=7966

"""
from __future__ import annotations

from cve_bin_tool.checkers import Checker


class SpeexChecker(Checker):
    CONTAINS_PATTERNS: list[str] = []
    FILENAME_PATTERNS: list[str] = []
    VERSION_PATTERNS = [
        r"speex(?:dec|enc)-([0-9]+\.[0-9]+(\.[0-9]+)?)",
        r"Unknown wb_mode_query request: \r?\nwarning: %s %d\r?\n([0-9]+\.[0-9]+(\.[0-9]+)?)",
        r"([0-9]+\.[0-9]+(\.[0-9]+)?)\r?\nUnknown wb_mode_query request:",
    ]
    VENDOR_PRODUCT = [("xiph", "speex")]
