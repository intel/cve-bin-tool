# Copyright (C) 2022 Orange
# SPDX-License-Identifier: GPL-3.0-or-later


"""
CVE checker for nettle

https://www.cvedetails.com/product/33288/Nettle-Project-Nettle.html?vendor_id=15791

Note: checker doesn't work on debian or openWRT (the version is not embedded at all in the binary code). Tests provided are opensuse-only.

"""
from __future__ import annotations

from cve_bin_tool.checkers import Checker


class NettleChecker(Checker):
    CONTAINS_PATTERNS: list[str] = []
    FILENAME_PATTERNS: list[str] = []
    VERSION_PATTERNS = [r"nettle[ -]([0-9]+\.[0-9]+\.?[0-9]*)"]
    VENDOR_PRODUCT = [("nettle_project", "nettle")]
