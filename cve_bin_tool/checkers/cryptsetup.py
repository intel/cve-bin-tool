# Copyright (C) 2021 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later


"""
CVE checker for cryptsetup

https://www.cvedetails.com/product/35660/?q=Cryptsetup

"""
from cve_bin_tool.checkers import Checker


class CryptsetupChecker(Checker):
    CONTAINS_PATTERNS = [
        r"Legacy offline reencryption already in-progress. Use cryptsetup-reencrypt utility.",
        r"Only LUKS2 format is currently supported. Please use cryptsetup-reencrypt tool for LUKS1.",
    ]
    FILENAME_PATTERNS = [r"cryptsetup"]
    VERSION_PATTERNS = [
        r"cryptsetup ([0-9]+\.[0-9]+\.[0-9]+)",
        r"cryptsetup library version %s.\r?\n([0-9]+\.[0-9]+\.[0-9]+)",
        r"([0-9]+\.[0-9]+\.[0-9]+)\r?\nCrypto backend \(%s\) initialized in cryptsetup",
    ]
    VENDOR_PRODUCT = [("cryptsetup_project", "cryptsetup")]
