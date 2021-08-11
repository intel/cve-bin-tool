# Copyright (C) 2021 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later

"""
CVE checker for libgcrypt

https://www.cvedetails.com/product/25777/Gnupg-Libgcrypt.html?vendor_id=4711
"""
from cve_bin_tool.checkers import Checker


class LibgcryptChecker(Checker):
    CONTAINS_PATTERNS = [
        "fork detection failed",
        "too many random bits requested",
        "severe error getting random",
    ]
    FILENAME_PATTERNS = [r"libgcrypt.so."]
    VERSION_PATTERNS = [r"Libgcrypt ([01]+\.[0-9]+\.[0-9]+)"]
    VENDOR_PRODUCT = [("gnupg", "libgcrypt")]
