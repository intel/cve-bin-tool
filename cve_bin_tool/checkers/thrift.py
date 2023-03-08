# Copyright (C) 2022 Orange
# SPDX-License-Identifier: GPL-3.0-or-later


"""
CVE checker for thrift

https://www.cvedetails.com/product/38295/Apache-Thrift.html?vendor_id=45

"""
from __future__ import annotations

from cve_bin_tool.checkers import Checker


class ThriftChecker(Checker):
    CONTAINS_PATTERNS: list[str] = []
    FILENAME_PATTERNS: list[str] = []
    VERSION_PATTERNS = [
        r"Thrift Compiler \(\r?\n([0-9]+\.[0-9]+\.[0-9]+)",
        r"thrift-([0-9]+\.[0-9]+\.[0-9]+)",
        r"thriftqt5-([0-9]+\.[0-9]+\.[0-9]+)",
        r"thriftnb-([0-9]+\.[0-9]+\.[0-9]+)",
        r"thriftz-([0-9]+\.[0-9]+\.[0-9]+)",
    ]
    VENDOR_PRODUCT = [("apache", "thrift")]
