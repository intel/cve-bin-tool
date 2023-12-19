# Copyright (C) 2021 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later

"""
CVE checker for GnuTLS
References:
https://www.cvedetails.com/vulnerability-list/vendor_id-72/product_id-4433/GNU-Gnutls.html
"""
from __future__ import annotations

from cve_bin_tool.checkers import Checker


class GnutlsChecker(Checker):
    # FIXME: fix contains pattern
    CONTAINS_PATTERNS: list[str] = []
    FILENAME_PATTERNS = [
        "gnutls-cli",
        "libgnutls.so",
        "libgnutls-dane.so",
        "gnutls-serv",
    ]
    VERSION_PATTERNS = [
        r"gnutls-cli ([0-9]+\.[0-9]+\.[0-9]+)",
        r"gnutls-serv ([0-9]+\.[0-9]+\.[0-9]+)",
        r"GnuTLS ([0-9]+\.[0-9]+\.[0-9]+)",
    ]
    VENDOR_PRODUCT = [("gnu", "gnutls")]
