# Copyright (C) 2022 Orange
# SPDX-License-Identifier: GPL-3.0-or-later


"""
CVE checker for timescaledb

https://www.cvedetails.com/product/111330/Timescale-Timescaledb.html?vendor_id=26620

Note: timescaledb is not provided by debian or openWRT. Tests provided are fedora-only.

"""
from __future__ import annotations

from cve_bin_tool.checkers import Checker


class TimescaledbChecker(Checker):
    CONTAINS_PATTERNS: list[str] = []
    FILENAME_PATTERNS: list[str] = []
    VERSION_PATTERNS = [r"timescaledb-([0-9]+\.[0-9]+\.[0-9]+)"]
    VENDOR_PRODUCT = [("timescale", "timescaledb")]
