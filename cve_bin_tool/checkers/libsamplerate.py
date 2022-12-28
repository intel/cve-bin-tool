# Copyright (C) 2022 Orange
# SPDX-License-Identifier: GPL-3.0-or-later


"""
CVE checker for libsamplerate

https://www.cvedetails.com/product/37074/Libsamplerate-Project-Libsamplerate.html?vendor_id=16339

"""
from __future__ import annotations

from cve_bin_tool.checkers import Checker


class LibsamplerateChecker(Checker):
    CONTAINS_PATTERNS: list[str] = []
    FILENAME_PATTERNS: list[str] = []
    VERSION_PATTERNS = ["libsamplerate\\-([0-9]+\\.[0-9]+\\.[0-9]+)"]
    VENDOR_PRODUCT = [("libsamplerate_project", "libsamplerate")]
