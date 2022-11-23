# Copyright (C) 2022 Orange
# SPDX-License-Identifier: GPL-3.0-or-later


"""
CVE checker for elfutils

https://www.cvedetails.com/product/27413/Elfutils-Project-Elfutils.html?vendor_id=13228

"""
from __future__ import annotations

from cve_bin_tool.checkers import Checker


class ElfutilsChecker(Checker):
    CONTAINS_PATTERNS: list[str] = []
    FILENAME_PATTERNS: list[str] = []
    VERSION_PATTERNS = [
        r"([0-9]+\.[0-9]+)\r?\nelfutils",
        r"elfutils\r?\n([0-9]+\.[0-9]+)",
    ]
    VENDOR_PRODUCT = [("elfutils_project", "elfutils")]
