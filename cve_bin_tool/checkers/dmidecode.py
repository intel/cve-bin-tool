# Copyright (C) 2023 Orange
# SPDX-License-Identifier: GPL-3.0-or-later


"""
CVE checker for dmidecode

https://www.cvedetails.com/product/138316/Nongnu-Dmidecode.html?vendor_id=6788

"""
from __future__ import annotations

from cve_bin_tool.checkers import Checker


class DmidecodeChecker(Checker):
    CONTAINS_PATTERNS: list[str] = []
    FILENAME_PATTERNS: list[str] = []
    VERSION_PATTERNS = [r"([0-9]+\.[0-9]+)\r?\n(?:# |)dmidecode"]
    VENDOR_PRODUCT = [("nongnu", "dmidecode")]
