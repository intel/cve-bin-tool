# Copyright (C) 2021 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later


"""
CVE checker for nessus

References:
https://www.cvedetails.com/vulnerability-list/vendor_id-12865/product_id-27428/Tenable-Nessus.html
"""
from cve_bin_tool.checkers import Checker


class NessusChecker(Checker):
    CONTAINS_PATTERNS = [
        r"you have deleted older versions nessus libraries from your system",
        r"server_info_nessusd_version",
        r"nessuslib_version",
        r"nessus_lib_version",
    ]
    FILENAME_PATTERNS = [r"libnessus"]
    VERSION_PATTERNS = [
        r"Nessus ([0-9]+\.[0-9]+\.[0-9]+)",
        r"libnessus.so.([0-9]+\.[0-9]+\.[0-9]+)",  # patterns like this aren't ideal
    ]
    VENDOR_PRODUCT = [("tenable", "nessus")]


"""
Using filenames (containing patterns like '.so' etc.) in the binaries as VERSION_PATTERNS aren't ideal.
The reason behind this is that these might depend on who packages the file (like it
might work on fedora but not on ubuntu)
"""
