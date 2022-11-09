# Copyright (C) 2022 Orange
# SPDX-License-Identifier: GPL-3.0-or-later


"""
CVE checker for mpv

https://www.cvedetails.com/product/43468/MPV-MPV.html?vendor_id=17607

"""
from __future__ import annotations

from cve_bin_tool.checkers import Checker


class MpvChecker(Checker):
    CONTAINS_PATTERNS: list[str] = []
    FILENAME_PATTERNS: list[str] = []
    VERSION_PATTERNS = [r"mpv ([0-9]+\.[0-9]+\.[0-9]+)"]
    VENDOR_PRODUCT = [("mpv", "mpv")]
