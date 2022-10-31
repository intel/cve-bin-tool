# Copyright (C) 2022 Orange
# SPDX-License-Identifier: GPL-3.0-or-later


"""
CVE checker for libvorbis

https://www.cvedetails.com/product/12156/Xiph.org-Libvorbis.html?vendor_id=7206

"""
from __future__ import annotations

from cve_bin_tool.checkers import Checker


class LibvorbisChecker(Checker):
    CONTAINS_PATTERNS: list[str] = []
    FILENAME_PATTERNS: list[str] = []
    VERSION_PATTERNS = ["libVorbis ([0-9]+\\.[0-9]+\\.[0-9]+)"]
    VENDOR_PRODUCT = [("xiph.org", "libvorbis")]
