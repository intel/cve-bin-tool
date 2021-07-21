# Copyright (C) 2021 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later


"""

CVE checker for TrouSerS

https://www.cvedetails.com/vendor/23743/?q=Trousers+Project

"""
from cve_bin_tool.checkers import Checker


class TrousersChecker(Checker):
    CONTAINS_PATTERNS = [
        r"TrouSerS Config file %s not found, using defaults.",
        r"TrouSerS Could not retrieve client address info",
        r"TrouSerS Could not set IPv6 socket option properly.",
        r"TrouSerS IPv4 support disabled by configuration option",
        r"TrouSerS IPv6 support disabled by configuration option",
    ]
    FILENAME_PATTERNS = [r"tcsd"]
    VERSION_PATTERNS = [r"trousers ([0-9]+\.[0-9]+\.[0-9]+)"]
    VENDOR_PRODUCT = [
        ("trustedcomputinggroup", "trousers"),
        ("suse", "trousers"),
        ("trousers_project", "trousers"),
    ]
