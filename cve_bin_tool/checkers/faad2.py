# Copyright (C) 2022 Orange
# SPDX-License-Identifier: GPL-3.0-or-later


"""
CVE checker for faad2:

https://www.cvedetails.com/product/14998/Audiocoding-Faad2.html?vendor_id=8551
https://www.cvedetails.com/product/38454/Audiocoding-Freeware-Advanced-Audio-Decoder-2.html?vendor_id=8551
https://www.cvedetails.com/product/101051/Faad2-Project-Faad2.html?vendor_id=25570

"""
from __future__ import annotations

from cve_bin_tool.checkers import Checker


class Faad2Checker(Checker):
    CONTAINS_PATTERNS: list[str] = []
    FILENAME_PATTERNS: list[str] = []
    VERSION_PATTERNS = [
        r"faad-([0-9]+\.[0-9]+\.[0-9]+)",
        r"TAG\r?\n([0-9]+\.[0-9]+\.[0-9]+)[A-Za-z \r?\n]+Copyright 2002-2004: Ahead Software AG",
    ]
    VENDOR_PRODUCT = [
        ("audiocoding", "faad2"),
        ("audiocoding", "freeware_advanced_audio_decoder_2"),
        ("faad2_project", "faad2"),
    ]
