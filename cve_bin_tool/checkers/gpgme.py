# Copyright (C) 2021 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later

"""
CVE checker for gpgme

https://www.cvedetails.com/product/94121/?q=Gpgme
https://www.cvedetails.com/product/10513/GNU-Gpgme.html?vendor_id=72

"""
from cve_bin_tool.checkers import Checker


class GpgmeChecker(Checker):
    CONTAINS_PATTERNS = []
    FILENAME_PATTERNS = [r"gpgme"]
    VERSION_PATTERNS = [
        r"This is GPGME ([0-9]+\.[0-9]+\.[0-9]+) \- The GnuPG Made Easy library",
        r"GPGME-Tool ([0-9]+\.[0-9]+\.[0-9]+) ready",
    ]
    VENDOR_PRODUCT = [("gnupg", "gpgme"), ("gnu", "gpgme")]
