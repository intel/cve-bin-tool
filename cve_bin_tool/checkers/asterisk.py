# Copyright (C) 2022 Orange
# SPDX-License-Identifier: GPL-3.0-or-later


"""
CVE checker for asterisk

https://www.cvedetails.com/product/3085/Digium-Asterisk.html?vendor_id=1802
https://www.cvedetails.com/product/10639/Asterisk-Asterisk.html?vendor_id=6284
https://www.cvedetails.com/product/113194/Sangoma-Asterisk.html?vendor_id=9238
https://www.cvedetails.com/product/12770/Asterisk-Open-Source.html?vendor_id=6284

"""
from __future__ import annotations

from cve_bin_tool.checkers import Checker


class AsteriskChecker(Checker):
    CONTAINS_PATTERNS: list[str] = []
    FILENAME_PATTERNS: list[str] = []
    VERSION_PATTERNS = [
        r"asterisk-([0-9]+\.[0-9]+\.[0-9]+)",
        r"ast_uuid_init\r?\n([0-9]+\.[0-9]+\.[0-9]+)",
    ]
    VENDOR_PRODUCT = [
        ("asterisk", "asterisk"),
        ("asterisk", "open_source"),
        ("digium", "asterisk"),
        ("sangoma", "asterisk"),
    ]
