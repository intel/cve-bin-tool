# Copyright (C) 2021 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later


"""
CVE checker for polarssl

This checker currently works on only fedora distribution, because of lack of common signatures
in other distributions, with unsuccessful attempts made for CentOS and ubuntu distributions.

https://www.cvedetails.com/product/22470/Polarssl-Polarssl.html?vendor_id=12001

"""
from cve_bin_tool.checkers import Checker


class PolarsslFedoraChecker(Checker):
    CONTAINS_PATTERNS = []
    FILENAME_PATTERNS = [r"libpolarssl.so."]
    VERSION_PATTERNS = [
        r"libpolarssl.so.([0-9]+\.[0-9]+\.[0-9]+)"
    ]  # patterns like this aren't ideal
    VENDOR_PRODUCT = [("polarssl", "polarssl")]


"""
Using filenames (containing patterns like '.so' etc.) in the binaries as VERSION_PATTERNS aren't ideal.
The reason behind this is that these might depend on who packages the file (like it 
might work on fedora but not on ubuntu)
"""
