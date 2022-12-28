# Copyright (C) 2021 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later


"""
CVE checker for bubblewrap

https://www.cvedetails.com/vendor/16078/?q=Bubblewrap+Project

"""
from __future__ import annotations

from cve_bin_tool.checkers import Checker


class BubblewrapChecker(Checker):
    CONTAINS_PATTERNS: list[str] = []
    FILENAME_PATTERNS = [r"bwrap"]
    VERSION_PATTERNS = [r"bubblewrap ([0-9]+\.[0-9]+\.[0-9]+)"]
    VENDOR_PRODUCT = [
        ("bubblewrap_project", "bubblewrap"),
        ("projectatomic", "bubblewrap"),
    ]
