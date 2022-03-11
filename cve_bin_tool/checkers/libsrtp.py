# Copyright (C) 2022 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later

"""
CVE checker for libsrtp

https://www.cvedetails.com/vulnerability-list/vendor_id-16/product_id-26868/version_id-502930/Cisco-Libsrtp--.html

"""

from cve_bin_tool.checkers import Checker


class LibsrtpChecker(Checker):
    CONTAINS_PATTERNS = [
        r"An implementation of the Secure Real-time Transport Protocol \(SRTP\)",
        r"This package provides an implementation of the Secure Real-time",
        r"Transport Protocol \(SRTP\), the Universal Security Transform \(UST\), and",
        r"a supporting cryptographic kernel\.",
    ]
    FILENAME_PATTERNS = [r"libsrtp"]
    VERSION_PATTERNS = [r"libsrtp[0-9]? ([0-9]+\.[0-9]+\.[0-9]+)"]
    VENDOR_PRODUCT = [("cisco", "libsrtp")]
