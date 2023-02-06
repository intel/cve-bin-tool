# Copyright (C) 2021 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later


"""
CVE checker for icecast

https://www.cvedetails.com/product/1194/Icecast-Icecast.html?vendor_id=693
https://www.cvedetails.com/product/31619/Xiph-Icecast.html?vendor_id=7966

"""
from __future__ import annotations

from cve_bin_tool.checkers import Checker


class IcecastChecker(Checker):
    CONTAINS_PATTERNS: list[str] = []
    FILENAME_PATTERNS = [r"icecast"]
    VERSION_PATTERNS = [r"Icecast ([0-9]+\.[0-9]+\.[0-9]+)"]
    VENDOR_PRODUCT = [("icecast", "icecast"), ("xiph", "icecast")]
