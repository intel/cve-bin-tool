# Copyright (C) 2022 Orange
# SPDX-License-Identifier: GPL-3.0-or-later

"""
CVE checker for file

https://www.cvedetails.com/product/2869/File-File.html?vendor_id=1661
https://www.cvedetails.com/product/10849/Gentoo-File.html?vendor_id=1594
https://www.cvedetails.com/product/17327/Christos-Zoulas-File.html?vendor_id=1997
https://www.cvedetails.com/product/30576/File-Project-File.html?vendor_id=15034

"""
from __future__ import annotations

from cve_bin_tool.checkers import Checker


class FileChecker(Checker):
    CONTAINS_PATTERNS: list[str] = []
    FILENAME_PATTERNS: list[str] = []
    VERSION_PATTERNS = [
        r"([0-9]+\.[0-9]+)\r?\n%s-%s\r?\nmagic file",
        r"([0-9]+\.[0-9]+)\r?\nmagic file",
    ]
    VENDOR_PRODUCT = [
        ("christos_zoulas", "file"),
        ("file", "file"),
        ("file_project", "file"),
        ("gentoo", "file"),
    ]
