# Copyright (C) 2024 Orange
# SPDX-License-Identifier: GPL-3.0-or-later


"""
CVE checker for libyaml

https://www.cvedetails.com/product/27063/Pyyaml-Libyaml.html?vendor_id=13115

"""
from __future__ import annotations

from cve_bin_tool.checkers import Checker


class LibyamlChecker(Checker):
    CONTAINS_PATTERNS: list[str] = []
    FILENAME_PATTERNS: list[str] = []
    VERSION_PATTERNS = [r"([0-9]+\.[0-9]+\.[0-9]+)[a-z_=&!>|()/ \.\-\r\n]*tag:yaml"]
    VENDOR_PRODUCT = [("pyyaml", "libyaml")]
