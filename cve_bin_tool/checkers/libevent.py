# Copyright (C) 2023 Orange
# SPDX-License-Identifier: GPL-3.0-or-later


"""
CVE checker for libevent:

https://www.cvedetails.com/product/10398/Niels-Provos-Libevent.html?vendor_id=2382
https://www.cvedetails.com/product/32303/Libevent-Project-Libevent.html?vendor_id=15590

"""
from __future__ import annotations

from cve_bin_tool.checkers import Checker


class LibeventChecker(Checker):
    CONTAINS_PATTERNS: list[str] = []
    FILENAME_PATTERNS: list[str] = []
    VERSION_PATTERNS = [
        r"libevent using: %s[a-zA-Z%:. \r\n]*([0-9]+\.[0-9]+\.[0-9]+)-stable",
        r"([0-9]+\.[0-9]+\.[0-9]+)-stable[0-9a-zA-Z|~,;!&+=*%_<>():'. \[\]\-\r\n]*libevent using:",
    ]
    VENDOR_PRODUCT = [("libevent_project", "libevent"), ("niels_provos", "libevent")]
