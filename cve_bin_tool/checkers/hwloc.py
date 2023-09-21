# Copyright (C) 2023 Orange
# SPDX-License-Identifier: GPL-3.0-or-later


"""
CVE checker for hwloc

https://www.cvedetails.com/product/160091/Open-mpi-Hwloc.html?vendor_id=32672

"""
from __future__ import annotations

from cve_bin_tool.checkers import Checker


class HwlocChecker(Checker):
    CONTAINS_PATTERNS: list[str] = []
    FILENAME_PATTERNS: list[str] = []
    VERSION_PATTERNS = [r"hwloc[a-zA-Z/%#() \-\.\r\n]*([0-9]+\.[0-9]+\.[0-9]+)"]
    VENDOR_PRODUCT = [("open-mpi", "hwloc")]
