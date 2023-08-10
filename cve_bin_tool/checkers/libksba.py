# Copyright (C) 2022 Orange
# SPDX-License-Identifier: GPL-3.0-or-later


"""
CVE checker for libksba:

https://www.cvedetails.com/product/139830/Gnupg-Libksba.html?vendor_id=4711

"""
from __future__ import annotations

from cve_bin_tool.checkers import Checker


class LibksbaChecker(Checker):
    CONTAINS_PATTERNS: list[str] = []
    FILENAME_PATTERNS: list[str] = []
    VERSION_PATTERNS = [r"Libksba ([0-9]+\.[0-9]+\.[0-9]+)"]
    VENDOR_PRODUCT = [("gnupg", "libksba")]
