# Copyright (C) 2021 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later


"""
CVE checker for tcpdump

https://www.cvedetails.com/product/10494/Tcpdump-Tcpdump.html?vendor_id=6197

"""
from cve_bin_tool.checkers import Checker


class TcpdumpChecker(Checker):
    CONTAINS_PATTERNS = []
    FILENAME_PATTERNS = [r"tcpdump"]
    VERSION_PATTERNS = [r"tcpdump-([0-9]+\.[0-9]+\.[0-9]+)"]
    VENDOR_PRODUCT = [("tcpdump", "tcpdump")]
