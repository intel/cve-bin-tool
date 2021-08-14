# Copyright (C) 2021 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later

"""
CVE checker for dnsmasq

 https://www.cvedetails.com/vulnerability-list/vendor_id-2959/product_id-5164/Dnsmasq-Dnsmasq.html

"""
from cve_bin_tool.checkers import Checker


class DnsmasqChecker(Checker):
    CONTAINS_PATTERNS = [
        r"Dnsmasq is free software, and you are welcome to redistribute it",
        # r"Allow access only to files owned by the user running dnsmasq\.",
        # r"Display dnsmasq version and copyright information\.",
    ]
    FILENAME_PATTERNS = [r"dnsmasq"]
    VERSION_PATTERNS = [r"dnsmasq-([0-9]+\.[0-9]+)"]
    VENDOR_PRODUCT = [
        ("dnsmasq", "dnsmasq"),
        ("thekelleys", "dnsmasq"),
        ("the_kelleys", "dnsmasq"),
    ]
