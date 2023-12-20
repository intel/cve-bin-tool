# Copyright (C) 2023 Orange
# SPDX-License-Identifier: GPL-3.0-or-later


"""
CVE checker for tar

https://www.cvedetails.com/product/1394/GNU-TAR.html?vendor_id=72

"""
from __future__ import annotations

from cve_bin_tool.checkers import Checker


class TarChecker(Checker):
    CONTAINS_PATTERNS: list[str] = []
    FILENAME_PATTERNS: list[str] = []
    VERSION_PATTERNS = [
        r"GNU tar[A-Za-z%:() \r\n]*([0-9]+\.[0-9]+)\r?\n",
        r"([0-9]+\.[0-9]+)\r?\nTAR_VERSION",
    ]
    VENDOR_PRODUCT = [("gnu", "tar")]
