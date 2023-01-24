# Copyright (C) 2021 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later


"""
CVE checker for openswan

https://www.cvedetails.com/product/57217/Xelerance-Openswan.html?vendor_id=20146

"""
from __future__ import annotations

from cve_bin_tool.checkers import Checker


class OpenswanChecker(Checker):
    CONTAINS_PATTERNS: list[str] = []
    FILENAME_PATTERNS = [
        r"klipsdebug",
        r"showhostkey",
        r"ranbits",
        r"eroute",
        r"showpolicy",
        r"spigrp",
        r"pluto",
        r"ikeping",
        r"rsasigkey",
    ]
    VERSION_PATTERNS = [r"Openswan ([0-9]+\.[0-9]+\.[0-9]+)"]
    VENDOR_PRODUCT = [("xelerance", "openswan")]
