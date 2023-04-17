# Copyright (C) 2022 Orange
# SPDX-License-Identifier: GPL-3.0-or-later


"""
CVE checker for tinyproxy

https://www.cvedetails.com/product/1178/Tinyproxy-Tinyproxy.html?vendor_id=692
https://www.cvedetails.com/product/20722/Banu-Tinyproxy.html?vendor_id=11393
https://www.cvedetails.com/product/39089/Tinyproxy-Project-Tinyproxy.html?vendor_id=16766

"""
from __future__ import annotations

from cve_bin_tool.checkers import Checker


class TinyproxyChecker(Checker):
    CONTAINS_PATTERNS: list[str] = []
    FILENAME_PATTERNS: list[str] = []
    VERSION_PATTERNS = ["tinyproxy\\/([0-9]+\\.[0-9]+\\.[0-9]+)"]
    VENDOR_PRODUCT = [
        ("banu", "tinyproxy"),
        ("tinyproxy", "tinyproxy"),
        ("tinyproxy_project", "tinyproxy"),
    ]
