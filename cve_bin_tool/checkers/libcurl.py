# Copyright (C) 2023 Orange
# SPDX-License-Identifier: GPL-3.0-or-later


"""
CVE checker for libcurl:

https://www.cvedetails.com/product/25085/Haxx-Libcurl.html?vendor_id=12682

"""
from __future__ import annotations

from cve_bin_tool.checkers import Checker


class LibcurlChecker(Checker):
    CONTAINS_PATTERNS: list[str] = []
    FILENAME_PATTERNS: list[str] = []
    VERSION_PATTERNS = [r"libcurl[ -/]([678]+\.[0-9]+\.[0-9]+)"]
    VENDOR_PRODUCT = [("haxx", "libcurl")]
