# Copyright (C) 2023 Orange
# SPDX-License-Identifier: GPL-3.0-or-later


"""
CVE checker for rpm

https://www.cvedetails.com/product/19571/RPM-RPM.html?vendor_id=5376

"""
from __future__ import annotations

from cve_bin_tool.checkers import Checker


class RpmChecker(Checker):
    CONTAINS_PATTERNS: list[str] = []
    FILENAME_PATTERNS: list[str] = []
    VERSION_PATTERNS = [r"rpm[a-z]*\-([0-9]+\.[0-9]+\.[0-9]+(\.[0-9]+)?)"]
    VENDOR_PRODUCT = [("rpm", "rpm")]
