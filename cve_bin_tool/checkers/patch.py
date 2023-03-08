# Copyright (C) 2022 Orange
# SPDX-License-Identifier: GPL-3.0-or-later


"""
CVE checker for patch

https://www.cvedetails.com/product/30942/GNU-Patch.html?vendor_id=72

"""
from __future__ import annotations

from cve_bin_tool.checkers import Checker


class PatchChecker(Checker):
    CONTAINS_PATTERNS: list[str] = []
    FILENAME_PATTERNS: list[str] = []
    VERSION_PATTERNS = [
        "([0-9]+\\.[0-9]+\\.[0-9]+)\\r?\\nGNU patch",
        "GNU patch\\r?\\n([0-9]+\\.[0-9]+\\.[0-9]+)",
    ]
    VENDOR_PRODUCT = [("gnu", "patch")]
