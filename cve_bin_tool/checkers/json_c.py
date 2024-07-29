# Copyright (C) 2022 Orange
# SPDX-License-Identifier: GPL-3.0-or-later


"""
CVE checker for json-c

https://www.cvedetails.com/product/27485/Json-c-Project-Json-c.html?vendor_id=13247
https://www.cvedetails.com/product/160989/Json-c-Json-c.html?vendor_id=32893

"""
from __future__ import annotations

from cve_bin_tool.checkers import Checker


class JsonCChecker(Checker):
    CONTAINS_PATTERNS: list[str] = []
    FILENAME_PATTERNS: list[str] = []
    VERSION_PATTERNS = [
        r"json-c-([0-9]+\.[0-9]+\.?[0-9]*)",
        r"([0-9]+\.[0-9]+\.?[0-9]*)\r?\njson-c",
        r"([0-9]+\.[0-9]+\.?[0-9]*)[a-zA-Z0-9,% *!_()='+:\"\.\-\\\r\n]*json_tokener_error",
    ]
    VENDOR_PRODUCT = [("json-c", "json-c"), ("json-c_project", "json-c")]
