# Copyright (C) 2022 Orange
# SPDX-License-Identifier: GPL-3.0-or-later


"""
CVE checker for miniupnpc

https://www.cvedetails.com/product/64765/Miniupnp-Project-Miniupnpc.html?vendor_id=12591

"""
from __future__ import annotations

from cve_bin_tool.checkers import Checker


class MiniupnpcChecker(Checker):
    CONTAINS_PATTERNS: list[str] = []
    FILENAME_PATTERNS: list[str] = []
    VERSION_PATTERNS = [
        r"MiniUPnPc/([0-9]+\.[0-9]+(\.[0-9]+)?)",
    ]
    VENDOR_PRODUCT = [("miniupnp_project", "miniupnpc")]
