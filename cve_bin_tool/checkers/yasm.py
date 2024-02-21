# Copyright (C) 2023 Orange
# SPDX-License-Identifier: GPL-3.0-or-later


"""
CVE checker for yasm

https://www.cvedetails.com/product/118056/Tortall-Yasm.html?vendor_id=27855
https://www.cvedetails.com/product/138490/Yasm-Project-Yasm.html?vendor_id=30316

"""
from __future__ import annotations

from cve_bin_tool.checkers import Checker


class YasmChecker(Checker):
    CONTAINS_PATTERNS: list[str] = []
    FILENAME_PATTERNS: list[str] = []
    VERSION_PATTERNS = [r"yasm ([0-9]+\.[0-9]+\.[0-9]+)"]
    VENDOR_PRODUCT = [("tortall", "yasm"), ("yasm_project", "yasm")]
