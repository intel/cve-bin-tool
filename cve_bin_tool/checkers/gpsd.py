# Copyright (C) 2022 Orange
# SPDX-License-Identifier: GPL-3.0-or-later


"""
CVE checker for gpsd

https://www.cvedetails.com/product/27059/Gpsd-Project-Gpsd.html?vendor_id=13114

"""
from __future__ import annotations

from cve_bin_tool.checkers import Checker


class GpsdChecker(Checker):
    CONTAINS_PATTERNS: list[str] = []
    FILENAME_PATTERNS: list[str] = []
    VERSION_PATTERNS = [r"gpsd\-([0-9]+\.[0-9]+)"]
    VENDOR_PRODUCT = [("gpsd_project", "gpsd")]
