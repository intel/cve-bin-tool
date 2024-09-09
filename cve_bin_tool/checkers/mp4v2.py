# Copyright (C) 2024 Orange
# SPDX-License-Identifier: GPL-3.0-or-later


"""
CVE checker for mp4v2

https://www.cvedetails.com/product/48319/Techsmith-Mp4v2.html?vendor_id=9035
https://www.cvedetails.com/product/44070/Mp4v2-Project-Mp4v2.html?vendor_id=17731
https://www.cvedetails.com/product/142097/Mp4v2-Mp4v2.html?vendor_id=30832

"""
from __future__ import annotations

from cve_bin_tool.checkers import Checker


class Mp4V2Checker(Checker):
    CONTAINS_PATTERNS: list[str] = []
    FILENAME_PATTERNS: list[str] = []
    VERSION_PATTERNS = [r"MP4v2\r?\nversion:\r?\n([0-9]+\.[0-9]+\.[0-9]+)"]
    VENDOR_PRODUCT = [
        ("mp4v2", "mp4v2"),
        ("mp4v2_project", "mp4v2"),
        ("techsmith", "mp4v2"),
    ]
