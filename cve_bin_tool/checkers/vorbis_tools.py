# Copyright (C) 2023 Orange
# SPDX-License-Identifier: GPL-3.0-or-later


"""
CVE checker for vorbis-tools

https://www.cvedetails.com/product/30949/Xiph-Vorbis-tools.html?vendor_id=7966

"""
from __future__ import annotations

from cve_bin_tool.checkers import Checker


class VorbisToolsChecker(Checker):
    CONTAINS_PATTERNS: list[str] = []
    FILENAME_PATTERNS: list[str] = []
    VERSION_PATTERNS = [r"([0-9]+\.[0-9]+\.[0-9]+)\r?\nvorbis-tools"]
    VENDOR_PRODUCT = [("xiph", "vorbis-tools")]
