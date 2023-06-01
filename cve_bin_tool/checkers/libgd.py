# Copyright (C) 2023 Orange
# SPDX-License-Identifier: GPL-3.0-or-later


"""
CVE checker for libgd

https://www.cvedetails.com/product/11233/Libgd-Libgd.html?vendor_id=6668
https://www.cvedetails.com/product/11517/Libgd-Gd-Graphics-Library.html?vendor_id=6668
https://www.cvedetails.com/product/117883/Gd-Graphics-Library-Project-Gd-Graphics-Library.html?vendor_id=27800

"""
from __future__ import annotations

from cve_bin_tool.checkers import Checker


class LibgdChecker(Checker):
    CONTAINS_PATTERNS: list[str] = []
    FILENAME_PATTERNS: list[str] = []
    VERSION_PATTERNS = [r"gd-tga:[a-zA-Z,'%!. \-\r\n]*([0-9]+\.[0-9]+\.[0-9]+)"]
    VENDOR_PRODUCT = [
        ("libgd", "libgd"),
        ("libgd", "gd_graphics_library"),
        ("gd_graphics_library_project", "gd_graphics_library"),
    ]
