# Copyright (C) 2022 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later


"""
CVE checker for firefox

https://www.cvedetails.com/product/3264/Mozilla-Firefox.html?vendor_id=452

"""
from __future__ import annotations

from cve_bin_tool.checkers import Checker


class FirefoxChecker(Checker):
    CONTAINS_PATTERNS: list[str] = []
    FILENAME_PATTERNS: list[str] = [r"firefox"]
    VERSION_PATTERNS = [
        r"firefox-([0-9]+.[0-9]+(.[0-9]+)?)",
        r'"name":"firefox","version":"([0-9]+.[0-9]+(.[0-9]+)?)',
    ]
    VENDOR_PRODUCT = [("mozilla", "firefox")]
