# Copyright (C) 2022 Orange
# SPDX-License-Identifier: GPL-3.0-or-later


"""
CVE checker for opencv

https://www.cvedetails.com/product/36994/Opencv-Opencv.html?vendor_id=16327

"""
from __future__ import annotations

from cve_bin_tool.checkers import Checker


class OpencvChecker(Checker):
    CONTAINS_PATTERNS: list[str] = []
    FILENAME_PATTERNS: list[str] = []
    VERSION_PATTERNS = [r"opencv-([0-9]+\.[0-9]+\.[0-9]+(\.[0-9]+)*)"]
    VENDOR_PRODUCT = [("opencv", "opencv")]
