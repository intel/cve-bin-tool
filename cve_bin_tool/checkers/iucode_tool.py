# Copyright (C) 2022 Orange
# SPDX-License-Identifier: GPL-3.0-or-later


"""
CVE checker for iucode-tool

https://www.cvedetails.com/product/65383/Iucode-tool-Project-Iucode-tool.html?vendor_id=21509

"""
from __future__ import annotations

from cve_bin_tool.checkers import Checker


class IucodeToolChecker(Checker):
    CONTAINS_PATTERNS: list[str] = []
    FILENAME_PATTERNS: list[str] = []
    VERSION_PATTERNS = ["iucode\\_tool ([0-9]+\\.[0-9]+\\.[0-9]+)"]
    VENDOR_PRODUCT = [("iucode-tool_project", "iucode-tool")]
