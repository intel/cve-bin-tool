# Copyright (C) 2022 Orange
# SPDX-License-Identifier: GPL-3.0-or-later


"""
CVE checker for e2fsprogs

https://www.cvedetails.com/product/12670/Ext2-Filesystems-Utilities-E2fsprogs.html?vendor_id=7512
https://www.cvedetails.com/product/31107/E2fsprogs-Project-E2fsprogs.html?vendor_id=15251

"""
from __future__ import annotations

from cve_bin_tool.checkers import Checker


class E2FsprogsChecker(Checker):
    CONTAINS_PATTERNS: list[str] = []
    FILENAME_PATTERNS: list[str] = []
    VERSION_PATTERNS = [
        r"e2fsprogs\r?\n([0-9]+\.[0-9]+\.[0-9]+)",
        r"([0-9]+\.[0-9]+\.[0-9]+)\r?\nError: ext2fs",
        r"EXT2FS Library version ([0-9]+\.[0-9]+\.[0-9]+)",
    ]
    VENDOR_PRODUCT = [
        ("ext2_filesystems_utilities", "e2fsprogs"),
        ("e2fsprogs_project", "e2fsprogs"),
    ]
