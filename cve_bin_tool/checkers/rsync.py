# Copyright (C) 2022 Orange
# SPDX-License-Identifier: GPL-3.0-or-later


"""
CVE checker for rsync

https://www.cvedetails.com/product/396/Andrew-Tridgell-Rsync.html?vendor_id=229
https://www.cvedetails.com/product/3171/Redhat-Rsync.html?vendor_id=25
https://www.cvedetails.com/product/11903/Rsync-Rsync.html?vendor_id=7059
https://www.cvedetails.com/product/13782/Samba-Rsync.html?vendor_id=102

"""
from __future__ import annotations

from cve_bin_tool.checkers import Checker


class RsyncChecker(Checker):
    CONTAINS_PATTERNS: list[str] = []
    FILENAME_PATTERNS: list[str] = []
    VERSION_PATTERNS = [r"([0-9]+\.[0-9]+\.[0-9]+)\r?\nrsync"]
    VENDOR_PRODUCT = [
        ("andrew_tridgell", "rsync"),
        ("redhat", "rsync"),
        ("rsync", "rsync"),
        ("samba", "rsync"),
    ]
