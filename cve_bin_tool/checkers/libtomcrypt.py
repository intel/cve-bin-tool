# Copyright (C) 2022 Orange
# SPDX-License-Identifier: GPL-3.0-or-later


"""
CVE checker for libtomcrypt

https://www.cvedetails.com/product/5271/Libtomcrypt-Libtomcrypt.html?vendor_id=3025
https://www.cvedetails.com/product/36162/Libtom-Libtomcrypt.html?vendor_id=16188

"""
from __future__ import annotations

from cve_bin_tool.checkers import Checker


class LibtomcryptChecker(Checker):
    CONTAINS_PATTERNS: list[str] = []
    FILENAME_PATTERNS = ["libtomcrypt.so"]
    VERSION_PATTERNS = [r"LibTomCrypt ([0-9]+\.[0-9]+(\.[0-9]+)*)"]
    VENDOR_PRODUCT = [("libtom", "libtomcrypt"), ("libtomcrypt", "libtomcrypt")]
