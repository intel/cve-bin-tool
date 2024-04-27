# Copyright (C) 2022 Orange
# SPDX-License-Identifier: GPL-3.0-or-later


"""
CVE checker for point-to-point_protocol

https://www.cvedetails.com/product/2091/Samba-PPP.html?vendor_id=102
https://www.cvedetails.com/product/61854/Point-to-point-Protocol-Project-Point-to-point-Protocol.html?vendor_id=20961

"""
from __future__ import annotations

from cve_bin_tool.checkers import Checker


class PppChecker(Checker):
    CONTAINS_PATTERNS: list[str] = []
    FILENAME_PATTERNS: list[str] = []
    VERSION_PATTERNS = [
        r"pppd/([0-9]+\.[0-9]+\.[0-9]+)",
        r"pppd[a-z, :%\)]*\r?\n([0-9]+\.[0-9]+\.[0-9]+)",
        r"([0-9]+\.[0-9]+\.[0-9]+)\r?\npppd",
    ]
    VENDOR_PRODUCT = [
        ("point-to-point_protocol_project", "point-to-point_protocol"),
        ("samba", "ppp"),
    ]
