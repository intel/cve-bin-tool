# Copyright (C) 2023 Orange
# SPDX-License-Identifier: GPL-3.0-or-later


"""
CVE checker for heimdal

https://www.cvedetails.com/product/42095/Heimdal-Project-Heimdal.html?vendor_id=17317

"""
from __future__ import annotations

from cve_bin_tool.checkers import Checker


class HeimdalChecker(Checker):
    CONTAINS_PATTERNS: list[str] = []
    FILENAME_PATTERNS: list[str] = []
    VERSION_PATTERNS = [r"Heimdal ([0-9]+\.[0-9]+\.[0-9]+)"]
    VENDOR_PRODUCT = [("heimdal_project", "heimdal")]
