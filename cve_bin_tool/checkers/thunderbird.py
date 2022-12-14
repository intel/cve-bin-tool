# Copyright (C) 2022 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later


"""
CVE checker for thunderbird

https://www.cvedetails.com/product/3678/Mozilla-Thunderbird.html?vendor_id=452

"""
from __future__ import annotations

from cve_bin_tool.checkers import Checker


class ThunderbirdChecker(Checker):
    CONTAINS_PATTERNS: list[str] = []
    FILENAME_PATTERNS: list[str] = [r"thunderbird"]
    VERSION_PATTERNS = [
        r"thunderbird-([0-9]+.[0-9]+(.[0-9]+)?)",
        r'"name":"thunderbird","version":"([0-9]+.[0-9]+(.[0-9]+)?)',
    ]
    VENDOR_PRODUCT = [("mozilla", "thunderbird")]
