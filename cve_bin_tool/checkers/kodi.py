# Copyright (C) 2023 Orange
# SPDX-License-Identifier: GPL-3.0-or-later


"""
CVE checker for kodi (formerly named xbmc)

https://www.cvedetails.com/product/28255/Xbmc-Xbmc.html?vendor_id=13578
https://www.cvedetails.com/product/36080/Kodi-Kodi.html?vendor_id=16145

"""
from __future__ import annotations

from cve_bin_tool.checkers import Checker


class KodiChecker(Checker):
    CONTAINS_PATTERNS: list[str] = []
    FILENAME_PATTERNS: list[str] = []
    VERSION_PATTERNS = [r"(?:kodi|xbmc)-([0-9]+\.[0-9]+)"]
    VENDOR_PRODUCT = [("kodi", "kodi"), ("xbmc", "xbmc")]
