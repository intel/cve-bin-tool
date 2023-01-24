# Copyright (C) 2022 Orange
# SPDX-License-Identifier: GPL-3.0-or-later


"""
CVE checker for libinput

https://www.cvedetails.com/product/116015/Freedesktop-Libinput.html?vendor_id=7971

"""
from __future__ import annotations

from cve_bin_tool.checkers import Checker


class LibinputChecker(Checker):
    CONTAINS_PATTERNS: list[str] = []
    FILENAME_PATTERNS: list[str] = []
    VERSION_PATTERNS = [r"libinput/doc/([0-9]+\.[0-9]+\.[0-9]+)"]
    VENDOR_PRODUCT = [("freedesktop", "libinput")]
