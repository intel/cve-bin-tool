# Copyright (C) 2022 Orange
# SPDX-License-Identifier: GPL-3.0-or-later

"""
CVE checker for graphicsmagick

https://www.cvedetails.com/product/13508/Imagemagick-Graphicsmagick.html?vendor_id=1749
https://www.cvedetails.com/product/4903/Graphicsmagick-Graphicsmagick.html?vendor_id=2802

"""
from __future__ import annotations

from cve_bin_tool.checkers import Checker


class GraphicsmagickChecker(Checker):
    CONTAINS_PATTERNS: list[str] = []
    FILENAME_PATTERNS: list[str] = []
    VERSION_PATTERNS = [r"GraphicsMagick ([0-9]+\.[0-9]+\.[0-9]+)"]
    VENDOR_PRODUCT = [
        ("graphicsmagick", "graphicsmagick"),
        ("imagemagick", "graphicsmagick"),
    ]
