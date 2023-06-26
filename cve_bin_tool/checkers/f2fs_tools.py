# Copyright (C) 2023 Orange
# SPDX-License-Identifier: GPL-3.0-or-later


"""
CVE checker for f2fs-tools

https://www.cvedetails.com/product/92738/F2fs-tools-Project-F2fs-tools.html?vendor_id=24355

"""
from __future__ import annotations

from cve_bin_tool.checkers import Checker


class F2FsToolsChecker(Checker):
    CONTAINS_PATTERNS: list[str] = []
    FILENAME_PATTERNS: list[str] = []
    VERSION_PATTERNS = [
        r"F2FS-tools: mkfs\.f2fs Ver: %s[A-Za-z0-9%=\-\[\]:_ \(\)\r\n\t]*([0-9]+\.[0-9]+\.[0-9]+)",
        r"([0-9]+\.[0-9]+\.[0-9]+)[A-Za-z0-9%/>=\-\[\]\.:~, \(\)\r\n\t]*Usage: fsck.f2fs",
    ]
    VENDOR_PRODUCT = [("f2fs-tools_project", "f2fs-tools")]
