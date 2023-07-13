# Copyright (C) 2021 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later


"""
CVE checker for gimp

https://www.cvedetails.com/product/17152/Gimp-Gimp.html?vendor_id=9605

"""
from __future__ import annotations

from cve_bin_tool.checkers import Checker


class GimpChecker(Checker):
    CONTAINS_PATTERNS: list[str] = []
    FILENAME_PATTERNS = [r"gimp"]
    VERSION_PATTERNS = [r"image-uri\r?\nGIMP ([0-9]+\.[0-9]+\.[0-9]+)"]
    VENDOR_PRODUCT = [("gimp", "gimp")]
