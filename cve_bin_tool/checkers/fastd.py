# Copyright (C) 2022 Orange
# SPDX-License-Identifier: GPL-3.0-or-later


"""
CVE checker for fastd

https://www.cvedetails.com/product/90086/Fastd-Project-Fastd.html?vendor_id=23901

"""
from __future__ import annotations

from cve_bin_tool.checkers import Checker


class FastdChecker(Checker):
    CONTAINS_PATTERNS: list[str] = []
    FILENAME_PATTERNS: list[str] = []
    VERSION_PATTERNS = ["fastd v([0-9]+)"]
    VENDOR_PRODUCT = [("fastd_project", "fastd")]
