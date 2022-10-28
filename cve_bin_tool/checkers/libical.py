# Copyright (C) 2021 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later

"""
CVE checker for libical

https://www.cvedetails.com/product/35602/Libical-Project-Libical.html?vendor_id=16032

"""
from __future__ import annotations

from cve_bin_tool.checkers import Checker


class LibicalChecker(Checker):
    CONTAINS_PATTERNS: list[str] = []
    FILENAME_PATTERNS = [r"libical"]
    VERSION_PATTERNS = [r"libical-([0-9]+\.[0-9]+(\.[0-9]+)?)"]
    VENDOR_PRODUCT = [("libical_project", "libical")]
