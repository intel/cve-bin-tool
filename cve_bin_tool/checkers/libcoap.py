# Copyright (C) 2023 Orange
# SPDX-License-Identifier: GPL-3.0-or-later


"""
CVE checker for libcoap:

https://www.cvedetails.com/product/143502/Libcoap-Libcoap.html?vendor_id=31037

"""
from __future__ import annotations

from cve_bin_tool.checkers import Checker


class LibcoapChecker(Checker):
    CONTAINS_PATTERNS: list[str] = []
    FILENAME_PATTERNS: list[str] = []
    VERSION_PATTERNS = [r"libcoap ([0-9]+\.[0-9]+\.[0-9]+)"]
    VENDOR_PRODUCT = [("libcoap", "libcoap")]
