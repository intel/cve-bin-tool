# Copyright (C) 2022 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later

"""
CVE checker for libebml

https://www.cvedetails.com/product/33126/Matroska-Libebml.html?vendor_id=7864

"""
from __future__ import annotations

from cve_bin_tool.checkers import Checker


class LibebmlChecker(Checker):
    CONTAINS_PATTERNS: list[str] = []
    FILENAME_PATTERNS = [r"libebml.so"]
    VERSION_PATTERNS = [
        r"libebml-([0-9]+\.[0-9]+\.[0-9]+)",
        r"([0-9]+\.[0-9]+\.[0-9]+)\nUnknown\nEBMLVoid",  # This string may be brittle to changes in string ordering
    ]
    VENDOR_PRODUCT = [("matroska", "libebml")]
