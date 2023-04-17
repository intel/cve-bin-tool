# Copyright (C) 2021 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later


"""
CVE checker for pcsc-lite

https://www.cvedetails.com/product/19618/?q=Pcsc-lite

"""
from __future__ import annotations

from cve_bin_tool.checkers import Checker


class PcscLiteChecker(Checker):
    CONTAINS_PATTERNS: list[str] = []
    FILENAME_PATTERNS = [r"pcscd"]
    VERSION_PATTERNS = [r"pcsc-lite ([0-9]+\.[0-9]+\.[0-9]+) daemon ready."]
    VENDOR_PRODUCT = [("muscle", "pcsc-lite")]
