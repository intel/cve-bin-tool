# Copyright (C) 2022 Orange
# SPDX-License-Identifier: GPL-3.0-or-later


"""
CVE checker for iptables

https://www.cvedetails.com/product/56953/Netfilter-Iptables.html?vendor_id=17890

"""
from __future__ import annotations

from cve_bin_tool.checkers import Checker


class IptablesChecker(Checker):
    CONTAINS_PATTERNS: list[str] = []
    FILENAME_PATTERNS: list[str] = []
    VERSION_PATTERNS = [
        r"\r?\n([0-9]{1,2}\.[0-9]+\.[0-9]+\.?[0-9]*)\r?\niptables",
        r"iptables-([0-9]+\.[0-9]+\.[0-9]+\.?[0-9]*)",
        r"iptables-rules>[a-zA-Z %:\r\n]*([0-9]+\.[0-9]+\.[0-9]+\.?[0-9]*)",
        r"iptables-save v%s on %s\r?\n([0-9]+\.[0-9]+\.[0-9]+\.?[0-9]*)",
    ]
    VENDOR_PRODUCT = [("netfilter", "iptables")]
