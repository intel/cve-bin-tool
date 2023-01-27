# Copyright (C) 2023 Orange
# SPDX-License-Identifier: GPL-3.0-or-later


"""
CVE checker for lxc

https://www.cvedetails.com/product/27105/Linuxcontainers-LXC.html?vendor_id=13134

"""
from __future__ import annotations

from cve_bin_tool.checkers import Checker


class LxcChecker(Checker):
    CONTAINS_PATTERNS: list[str] = []
    FILENAME_PATTERNS: list[str] = []
    VERSION_PATTERNS = [r"([0-9]+\.[0-9]+\.[0-9]+)[a-zA-Z:./ %\r\n]*lxc"]
    VENDOR_PRODUCT = [("linuxcontainers", "lxc")]
