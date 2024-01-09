# Copyright (C) 2024 Orange
# SPDX-License-Identifier: GPL-3.0-or-later


"""
CVE checker for micropython

https://www.cvedetails.com/product/167231/Micropython-Micropython.html?vendor_id=34177

"""
from __future__ import annotations

from cve_bin_tool.checkers import Checker


class MicropythonChecker(Checker):
    CONTAINS_PATTERNS: list[str] = []
    FILENAME_PATTERNS: list[str] = []
    VERSION_PATTERNS = [r"MicroPython v([0-9]+\.[0-9]+\.[0-9]+)"]
    VENDOR_PRODUCT = [("micropython", "micropython")]
