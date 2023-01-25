# Copyright (C) 2021 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later


"""
CVE checker for libarchive

https://www.cvedetails.com/product/11632/Freebsd-Libarchive.html?vendor_id=6
https://www.cvedetails.com/product/26168/Libarchive-Libarchive.html?vendor_id=12872

"""
from __future__ import annotations

from cve_bin_tool.checkers import Checker


class LibarchiveChecker(Checker):
    CONTAINS_PATTERNS: list[str] = []
    FILENAME_PATTERNS = [r"libarchive.so"]
    VERSION_PATTERNS = [r"libarchive ([0-9]+\.[0-9]+\.[0-9]+)"]
    VENDOR_PRODUCT = [("freebsd", "libarchive"), ("libarchive", "libarchive")]
