# Copyright (C) 2022 Orange
# SPDX-License-Identifier: GPL-3.0-or-later


"""
CVE checker for miniupnpd

https://www.cvedetails.com/product/24263/Miniupnp-Project-Miniupnpd.html?vendor_id=12591
https://www.cvedetails.com/product/54506/Miniupnp.free-Miniupnpd.html?vendor_id=19867

"""
from __future__ import annotations

from cve_bin_tool.checkers import Checker


class MiniupnpdChecker(Checker):
    CONTAINS_PATTERNS: list[str] = []
    FILENAME_PATTERNS: list[str] = []
    VERSION_PATTERNS = [
        r"MiniUPnPd/([0-9]+\.[0-9]+(\.[0-9]+)?)",
    ]
    VENDOR_PRODUCT = [("miniupnp_project", "miniupnpd"), ("miniupnp.free", "miniupnpd")]
