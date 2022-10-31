# Copyright (C) 2021 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later


"""
CVE checker for netpbm

https://www.cvedetails.com/product/2877/Netpbm-Netpbm.html?vendor_id=1666

"""
from __future__ import annotations

from cve_bin_tool.checkers import Checker


class NetpbmChecker(Checker):
    CONTAINS_PATTERNS: list[str] = []
    FILENAME_PATTERNS = [r"libnetpbm.so"]
    VERSION_PATTERNS = [r"Netpbm ([0-9]+\.[0-9]+\.[0-9]+)"]
    VENDOR_PRODUCT = [("netpbm", "netpbm")]
