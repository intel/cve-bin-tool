# Copyright (C) 2021 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later

"""
CVE checker for GNUPG

https://www.cvedetails.com/vulnerability-list/vendor_id-4711/product_id-8075/Gnupg-Gnupg.html

"""
from cve_bin_tool.checkers import Checker


class GnupgChecker(Checker):
    CONTAINS_PATTERNS = []
    FILENAME_PATTERNS = [
        "gpg",
        "g13",
    ]
    VERSION_PATTERNS = [
        r"GNU Privacy Guard's OpenPGP server ([0-9]+\.[0-9]+\.[0-9]+) ready",
        r"GNU Privacy Guard's G13 server ([0-9]+\.[0-9]+\.[0-9]+) ready",
    ]
    VENDOR_PRODUCT = [("gnupg", "gnupg")]
