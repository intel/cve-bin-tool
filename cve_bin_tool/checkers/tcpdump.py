# Copyright (C) 2021 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later


"""
CVE checker for tcpdump

https://www.cvedetails.com/product/10494/Tcpdump-Tcpdump.html?vendor_id=6197

"""
from __future__ import annotations

from cve_bin_tool.checkers import Checker


class TcpdumpChecker(Checker):
    CONTAINS_PATTERNS: list[str] = []
    FILENAME_PATTERNS = [r"tcpdump"]
    # lookup_{emem,protoid} are static functions provided by tcpdump in addrtoname.c
    VERSION_PATTERNS = [
        r"tcpdump-([0-9]+\.[0-9]+\.[0-9]+)",
        r"([0-9]+\.[0-9]+\.[0-9]+)\r?\n[0-9a-f]*lookup_",
    ]
    VENDOR_PRODUCT = [("tcpdump", "tcpdump")]
