# Copyright (C) 2022 Orange
# SPDX-License-Identifier: GPL-3.0-or-later


"""
CVE checker for haserl

https://www.cvedetails.com/product/82440/Haserl-Project-Haserl.html?vendor_id=23119

"""
from __future__ import annotations

from cve_bin_tool.checkers import Checker


class HaserlChecker(Checker):
    CONTAINS_PATTERNS: list[str] = []
    FILENAME_PATTERNS: list[str] = []
    VERSION_PATTERNS = ["haserl version ([0-9]+\\.[0-9]+\\.[0-9]+)"]
    VENDOR_PRODUCT = [("haserl_project", "haserl")]
