# Copyright (C) 2022 Orange
# SPDX-License-Identifier: GPL-3.0-or-later


"""
CVE checker for ntpsec

https://www.cvedetails.com/product/35933/Ntpsec-Ntpsec.html?vendor_id=16112

"""
from __future__ import annotations

from cve_bin_tool.checkers import Checker


class NtpsecChecker(Checker):
    CONTAINS_PATTERNS: list[str] = []
    FILENAME_PATTERNS: list[str] = []
    VERSION_PATTERNS = [r"([0-9]+\.[0-9]+\.[0-9]+)[0-9A-Z-: ]*\r?\n[a-z]* ntpsec"]
    VENDOR_PRODUCT = [("ntpsec", "ntpsec")]
