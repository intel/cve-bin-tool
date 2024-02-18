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
        # Alternate optional contains patterns,
        # see https://github.com/intel/cve-bin-tool/tree/main/cve_bin_tool/checkers#helper-script for more details
        # r"/bind9.xsl",
    ]
    FILENAME_PATTERNS = [
        r"named",
        r"liblwres\.so",
        r"libdns([-_]?(\d+\.)+\d.*)?\.so",
        r"libirs([-_]?(\d+\.)+\d.*)?\.so",
        r"libisc([-_]?(\d+\.)+\d.*)?\.so",
        r"libisccc([-_]?(\d+\.)+\d.*)?\.so",
        r"libisccfg([-_]?(\d+\.)+\d.*)?\.so",
        r"libns([-_]?(\d+\.)+\d.*)?\.so",
    ]
    VERSION_PATTERNS = [
        r"version: BIND ([0-9]+\.[0-9]+\.[0-9]+)",  # for .rpm, .tgz, etc.
        r"(?:lib|/)bind[0-9]*-([0-9]+\.[0-9]+\.[0-9]+)",  # for .deb
        r"/bind9-([0-9]+\.[0-9]+\.[0-9]+)",  # using buildpath if included
        # If you trust the filenames to contain the right version number enable the following regular expressions:
        # r"libisc-([0-9]+\.[0-9]+\.[0-9]+)", # for libisc
        # r"libisccfg-([0-9]+\.[0-9]+\.[0-9]+)", # for libisccfg
        # r"libisccc-([0-9]+\.[0-9]+\.[0-9]+)", #for libisccc
        # r"libns-([0-9]+\.[0-9]+\.[0-9]+)", #for libns
        # r"libdns-([0-9]+\.[0-9]+\.[0-9]+)" #for libdns
    ]
    VENDOR_PRODUCT = [("isc", "bind")]
