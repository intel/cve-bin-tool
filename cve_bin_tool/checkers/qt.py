# Copyright (C) 2021 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later


"""
CVE checker for qt

https://www.cvedetails.com/product/10758/QT-QT.html?vendor_id=6363
https://www.cvedetails.com/product/24410/Digia-QT.html?vendor_id=12593

"""
from __future__ import annotations

from cve_bin_tool.checkers import Checker


class QtChecker(Checker):
    CONTAINS_PATTERNS: list[str] = []
    FILENAME_PATTERNS = [
        r"libqt-mt.so",
        r"libQtTest.so",
    ]
    VERSION_PATTERNS = [
        r"Qt ([0-9]+\.[0-9]+\.[0-9]+)",
        r"QTest library ([0-9]+\.[0-9]+\.[0-9]+)",
    ]
    VENDOR_PRODUCT = [("qt", "qt"), ("digia", "qt")]
