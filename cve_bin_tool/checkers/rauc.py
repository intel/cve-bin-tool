# Copyright (C) 2023 Orange
# SPDX-License-Identifier: GPL-3.0-or-later


"""
CVE checker for rauc

https://www.cvedetails.com/product/89460/Pengutronix-Rauc.html?vendor_id=20490

"""
from __future__ import annotations

from cve_bin_tool.checkers import Checker


class RaucChecker(Checker):
    CONTAINS_PATTERNS: list[str] = []
    FILENAME_PATTERNS: list[str] = []
    VERSION_PATTERNS = [r"rauc ([0-9]+\.[0-9]+(\.[0-9]+)?)"]
    VENDOR_PRODUCT = [("pengutronix", "rauc")]
