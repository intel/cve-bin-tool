# Copyright (C) 2023 Orange
# SPDX-License-Identifier: GPL-3.0-or-later


"""
CVE checker for civetweb

https://www.cvedetails.com/product/47117/Civetweb-Project-Civetweb.html?vendor_id=18572

"""
from __future__ import annotations

from cve_bin_tool.checkers import Checker


class CivetwebChecker(Checker):
    CONTAINS_PATTERNS: list[str] = []
    FILENAME_PATTERNS: list[str] = []
    VERSION_PATTERNS = [r"civetweb[A-Za-z /_,%:\(\)\-\r\n]*([0-9]+\.[0-9]+)"]
    VENDOR_PRODUCT = [("civetweb_project", "civetweb")]
