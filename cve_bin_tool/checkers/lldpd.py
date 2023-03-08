# Copyright (C) 2022 Orange
# SPDX-License-Identifier: GPL-3.0-or-later


"""
CVE checker for lldpd

https://www.cvedetails.com/product/64930/Lldpd-Project-Lldpd.html?vendor_id=21429

"""
from __future__ import annotations

from cve_bin_tool.checkers import Checker


class LldpdChecker(Checker):
    CONTAINS_PATTERNS: list[str] = []
    FILENAME_PATTERNS: list[str] = []
    VERSION_PATTERNS = ["lldpd ([0-9]+\\.[0-9]+\\.[0-9]+)"]
    VENDOR_PRODUCT = [("lldpd_project", "lldpd")]
