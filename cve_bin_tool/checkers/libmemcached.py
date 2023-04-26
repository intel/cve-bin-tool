# Copyright (C) 2023 Orange
# SPDX-License-Identifier: GPL-3.0-or-later


"""
CVE checker for libmemcached

https://www.cvedetails.com/product/136769/Awesome-Libmemcached.html?vendor_id=28345

"""
from __future__ import annotations

from cve_bin_tool.checkers import Checker


class LibmemcachedChecker(Checker):
    CONTAINS_PATTERNS: list[str] = []
    FILENAME_PATTERNS: list[str] = []
    VERSION_PATTERNS = [
        r"([0-9]+\.[0-9]+\.[0-9]+)\r?\nversion\r?\n(?:./src/|)libmemcached",
        r"mem(?:aslap|capable|cat|cp|dump|error|exist|flush|parse|ping|rm|slap|stat|touch)-([0-9]+\.[0-9]+\.[0-9]+)",
    ]
    VENDOR_PRODUCT = [("awesome", "libmemcached")]
