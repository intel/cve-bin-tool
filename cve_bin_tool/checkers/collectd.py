# Copyright (C) 2022 Orange
# SPDX-License-Identifier: GPL-3.0-or-later


"""
CVE checker for collectd

https://www.cvedetails.com/product/20310/Collectd-Collectd.html?vendor_id=11242

"""
from __future__ import annotations

from cve_bin_tool.checkers import Checker


class CollectdChecker(Checker):
    CONTAINS_PATTERNS: list[str] = []
    FILENAME_PATTERNS: list[str] = []
    VERSION_PATTERNS = ["collectd ([0-9]+\\.[0-9]+\\.[0-9]+)"]
    VENDOR_PRODUCT = [("collectd", "collectd")]
