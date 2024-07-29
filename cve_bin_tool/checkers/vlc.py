# Copyright (C) 2023 Orange
# SPDX-License-Identifier: GPL-3.0-or-later


"""
CVE checker for vlc

https://www.cvedetails.com/product/9876/Videolan-VLC.html?vendor_id=5842
https://www.cvedetails.com/product/9978/Videolan-Vlc-Media-Player.html?vendor_id=5842

"""
from __future__ import annotations

from cve_bin_tool.checkers import Checker


class VlcChecker(Checker):
    CONTAINS_PATTERNS: list[str] = []
    FILENAME_PATTERNS: list[str] = []
    VERSION_PATTERNS = [r"VLC/([0-9]+\.[0-9]+\.[0-9]+(\.[0-9]+)?)"]
    VENDOR_PRODUCT = [("videolan", "vlc"), ("videolan", "vlc_media_player")]
