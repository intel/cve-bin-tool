# Copyright (C) 2023 Orange
# SPDX-License-Identifier: GPL-3.0-or-later


"""
CVE checker for runc

https://www.cvedetails.com/product/60655/Linuxfoundation-Runc.html?vendor_id=11448

"""
from __future__ import annotations

from cve_bin_tool.checkers import Checker


class RuncChecker(Checker):
    CONTAINS_PATTERNS: list[str] = []
    FILENAME_PATTERNS: list[str] = []
    VERSION_PATTERNS = [r"runc-([0-9]+\.[0-9]+\.[0-9]+)"]
    VENDOR_PRODUCT = [("linuxfoundation", "runc")]
