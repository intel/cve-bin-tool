# Copyright (C) 2023 Orange
# SPDX-License-Identifier: GPL-3.0-or-later


"""
CVE checker for jq

https://www.cvedetails.com/product/33780/Jq-Project-JQ.html?vendor_id=15837
https://www.cvedetails.com/product/166422/Jqlang-JQ.html?vendor_id=33921

"""
from __future__ import annotations

from cve_bin_tool.checkers import Checker


class JqChecker(Checker):
    CONTAINS_PATTERNS: list[str] = []
    FILENAME_PATTERNS: list[str] = []
    VERSION_PATTERNS = [
        r"jq-([0-9]+\.[0-9]+\.[0-9]+)",
        r"([0-9]+\.[0-9]+)[a-zA-Z0-9:\-\r\n]*jq[ :]",
    ]
    VENDOR_PRODUCT = [("jq_project", "jq"), ("jqlang", "jq")]
