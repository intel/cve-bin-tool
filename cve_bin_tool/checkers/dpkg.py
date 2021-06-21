# Copyright (C) 2021 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later


"""
CVE checker for dpkg

https://www.cvedetails.com/product/18928/?q=Dpkg

"""
from cve_bin_tool.checkers import Checker


class DpkgChecker(Checker):
    CONTAINS_PATTERNS = [
        r"unable to access dpkg status area",
        r"multiple non-coinstallable package instances present; most probably due to an upgrade from an unofficial dpkg",
    ]
    FILENAME_PATTERNS = [r"dpkg"]
    VERSION_PATTERNS = [
        r"dpkg-([0-9]+\.[0-9]+\.[0-9]+)",
        r"dpkg-deb-([0-9]+\.[0-9]+\.[0-9]+)",
        r"dpkg-query-([0-9]+\.[0-9]+\.[0-9]+)",
        r"dpkg-divert-([0-9]+\.[0-9]+\.[0-9]+)",
    ]
    VENDOR_PRODUCT = [("debian", "dpkg")]
