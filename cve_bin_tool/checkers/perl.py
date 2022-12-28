# Copyright (C) 2022 Orange
# SPDX-License-Identifier: GPL-3.0-or-later


"""
CVE checker for perl

https://www.cvedetails.com/product/135/Larry-Wall-Perl.html?vendor_id=81
https://www.cvedetails.com/product/13879/Perl-Perl.html?vendor_id=1885

"""
from __future__ import annotations

from cve_bin_tool.checkers import Checker


class PerlChecker(Checker):
    CONTAINS_PATTERNS: list[str] = []
    FILENAME_PATTERNS: list[str] = []
    VERSION_PATTERNS = [
        r"perl/([0-9]+\.[0-9]+\.[0-9]+)",
        r"PERL[A-Z_]*\r?\nv([0-9]+\.[0-9]+\.[0-9]+)",
    ]
    VENDOR_PRODUCT = [
        ("larry_wall", "perl"),
        ("perl", "perl"),
    ]
