# Copyright (C) 2021 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later


"""
CVE checker for bind

https://www.cvedetails.com/product/144/ISC-Bind.html?vendor_id=64

"""
from cve_bin_tool.checkers import Checker


class BindChecker(Checker):
    CONTAINS_PATTERNS = [
        r"bind9_check_key",
        r"bind9_check_namedconf",
        # r"/bind9.xsl",
    ]
    FILENAME_PATTERNS = [r"named"]
    VERSION_PATTERNS = [
        r"BIND ([0-9]+\.[0-9]+\.[0-9]+)",  # for .rpm, .tgz, etc.
        r"bind[0-9]-([0-9]+\.[0-9]+\.[0-9]+)",  # for .deb
    ]
    VENDOR_PRODUCT = [("isc", "bind")]
