# Copyright (C) 2023 Orange
# SPDX-License-Identifier: GPL-3.0-or-later


"""
CVE checker for capnproto:

https://www.cvedetails.com/product/37224/Capnproto-Capnproto.html?vendor_id=16364

"""
from __future__ import annotations

from cve_bin_tool.checkers import Checker


class CapnprotoChecker(Checker):
    CONTAINS_PATTERNS: list[str] = []
    FILENAME_PATTERNS: list[str] = []
    VERSION_PATTERNS = [
        r"Cap'n Proto version ([0-9]+\.[0-9]+\.[0-9]+)",
        r"libcapnp-([0-9]+\.[0-9]+\.[0-9]+)",
    ]
    VENDOR_PRODUCT = [("capnproto", "capnproto")]
