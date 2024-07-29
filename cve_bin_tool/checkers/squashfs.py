# Copyright (C) 2022 Orange
# SPDX-License-Identifier: GPL-3.0-or-later


"""
CVE checker for squashfs

https://www.cvedetails.com/product/37102/Squashfs-Project-Squashfs.html?vendor_id=16355
https://www.cvedetails.com/product/99849/Squashfs-tools-Project-Squashfs-tools.html?vendor_id=25307

"""
from __future__ import annotations

from cve_bin_tool.checkers import Checker


class SquashfsChecker(Checker):
    CONTAINS_PATTERNS: list[str] = []
    FILENAME_PATTERNS: list[str] = []
    VERSION_PATTERNS = [r"squashfs version ([0-9]+\.[0-9]+\.?[0-9]*)"]
    VENDOR_PRODUCT = [
        ("squashfs_project", "squashfs"),
        ("squashfs-tools_project", "squashfs-tools"),
    ]
