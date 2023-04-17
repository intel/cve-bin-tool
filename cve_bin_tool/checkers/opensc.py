# Copyright (C) 2023 Orange
# SPDX-License-Identifier: GPL-3.0-or-later


"""
CVE checker for opensc

https://www.cvedetails.com/product/14674/Opensc-project-Opensc.html?vendor_id=8404
https://www.cvedetails.com/product/49900/Opensc-Project-Opensc.html?vendor_id=19215

"""
from __future__ import annotations

from cve_bin_tool.checkers import Checker


class OpenscChecker(Checker):
    CONTAINS_PATTERNS: list[str] = []
    FILENAME_PATTERNS: list[str] = []
    VERSION_PATTERNS = [
        r"([0-9]+\.[0-9]+\.[0-9]+)\r?\nOpenSC",
        r"\r?\n([0-9]+\.[0-9]+\.[0-9]+)[a-zA-Z0-9 _'\./:%\?\-\(\)\r\n]*opensc",
    ]
    VENDOR_PRODUCT = [("opensc-project", "opensc"), ("opensc_project", "opensc")]
