# Copyright (C) 2022 Orange
# SPDX-License-Identifier: GPL-3.0-or-later


"""
CVE checker for netatalk

https://www.cvedetails.com/product/15754/Netatalk-Netatalk.html?vendor_id=2680

"""
from __future__ import annotations

from cve_bin_tool.checkers import Checker


class NetatalkChecker(Checker):
    CONTAINS_PATTERNS: list[str] = []
    FILENAME_PATTERNS: list[str] = []
    VERSION_PATTERNS = [
        r"netatalk/afppasswd\r?\n([0-9]+\.[0-9]+\.[0-9]+)",
        r"([0-9]+\.[0-9]+\.[0-9]+)\r?\nad \(Netatalk",
        r"([0-9]+\.[0-9]+\.[0-9]+)\r?\nafpd \%s \- Apple Filing Protocol \(AFP\) daemon of Netatalk",
        r"([0-9]+\.[0-9]+\.[0-9]+)\r?\ncnid\_dbd \(Netatalk",
        r"([0-9]+\.[0-9]+\.[0-9]+)\r?\ncnid\_metad \(Netatalk",
        r"([0-9]+\.[0-9]+\.[0-9]+)\r?\nnetatalk",
    ]
    VENDOR_PRODUCT = [("netatalk", "netatalk")]
