# Copyright (C) 2022 Orange
# SPDX-License-Identifier: GPL-3.0-or-later


"""
CVE checker for flac:

https://www.cvedetails.com/product/12329/Flac-Libflac.html?vendor_id=7327
https://www.cvedetails.com/product/46017/Flac-Project-Flac.html?vendor_id=17957

"""
from __future__ import annotations

from cve_bin_tool.checkers import Checker


class FlacChecker(Checker):
    CONTAINS_PATTERNS: list[str] = []
    FILENAME_PATTERNS: list[str] = []
    VERSION_PATTERNS = [
        r"flac-([0-9]+\.[0-9]+\.[0-9]+)",
        r"reference libFLAC ([0-9]+\.[0-9]+\.[0-9]+)",
    ]
    VENDOR_PRODUCT = [("flac", "libflac"), ("flac_project", "flac")]
