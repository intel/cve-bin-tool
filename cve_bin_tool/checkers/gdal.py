# Copyright (C) 2023 Orange
# SPDX-License-Identifier: GPL-3.0-or-later


"""
CVE checker for gdal

https://www.cvedetails.com/product/6063/Gdal-Gdal.html?vendor_id=3467
https://www.cvedetails.com/product/75959/Osgeo-Gdal.html?vendor_id=21030

"""
from __future__ import annotations

from cve_bin_tool.checkers import Checker


class GdalChecker(Checker):
    CONTAINS_PATTERNS: list[str] = []
    FILENAME_PATTERNS: list[str] = []
    VERSION_PATTERNS = [r"gdal-([0-9]+\.[0-9]+\.[0-9]+)"]
    VENDOR_PRODUCT = [("gdal", "gdal"), ("osgeo", "gdal")]
