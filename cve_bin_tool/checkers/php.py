# Copyright (C) 2023 Orange
# SPDX-License-Identifier: GPL-3.0-or-later


"""
CVE checker for php

https://www.cvedetails.com/product/128/PHP-PHP.html?vendor_id=74

"""
from __future__ import annotations

from cve_bin_tool.checkers import Checker


class PhpChecker(Checker):
    CONTAINS_PATTERNS: list[str] = []
    FILENAME_PATTERNS: list[str] = []
    VERSION_PATTERNS = [r"PHP/([0-9]+\.[0-9]+\.[0-9]+)"]
    VENDOR_PRODUCT = [("php", "php")]
