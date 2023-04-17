# Copyright (C) 2022 Orange
# SPDX-License-Identifier: GPL-3.0-or-later


"""
CVE checker for procps-ng

https://www.cvedetails.com/product/52275/Procps-Project-Procps.html?vendor_id=19678
https://www.cvedetails.com/product/60812/Procps-ng-Project-Procps-ng.html?vendor_id=20741

"""
from __future__ import annotations

from cve_bin_tool.checkers import Checker


class ProcpsNgChecker(Checker):
    CONTAINS_PATTERNS: list[str] = []
    FILENAME_PATTERNS: list[str] = []
    VERSION_PATTERNS = [r"procps-ng ([0-9]+\.[0-9]+\.[0-9]+)"]
    VENDOR_PRODUCT = [("procps_project", "procps"), ("procps-ng_project", "procps-ng")]
