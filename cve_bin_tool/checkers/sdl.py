# Copyright (C) 2023 Orange
# SPDX-License-Identifier: GPL-3.0-or-later


"""
CVE checker for simple_directmedia_layer

https://www.cvedetails.com/product/53308/Libsdl-Simple-Directmedia-Layer.html?vendor_id=17090

"""
from __future__ import annotations

from cve_bin_tool.checkers import Checker


class SdlChecker(Checker):
    CONTAINS_PATTERNS: list[str] = []
    FILENAME_PATTERNS: list[str] = []
    VERSION_PATTERNS = [r"(?:sdl2|SDL2|SDL-release)-([0-9]+\.[0-9]+\.[0-9]+)"]
    VENDOR_PRODUCT = [("libsdl", "simple_directmedia_layer")]
