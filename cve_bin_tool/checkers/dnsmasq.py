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
        # Alternate optional contains patterns,
        # see https://github.com/intel/cve-bin-tool/tree/main/cve_bin_tool/checkers#helper-script for more details
        # r"Allow access only to files owned by the user running dnsmasq\.",
        # r"Display dnsmasq version and copyright information\.",
    ]
    FILENAME_PATTERNS = [r"dnsmasq"]
    VERSION_PATTERNS = [
        r"dnsmasq-[a-z_]*([0-9]+\.[0-9]+)",
        r"([0-9]+\.[0-9]+)\r?\nDnsmasq version %s",
        r"Dnsmasq version (?:|%s  %s\r?\n)([0-9]+\.[0-9]+)",
        r"([0-9]+\.[0-9]+)\r?\nstarted, version %s DNS disabled",
    ]
    VENDOR_PRODUCT = [
        ("dnsmasq", "dnsmasq"),
        ("thekelleys", "dnsmasq"),
        ("the_kelleys", "dnsmasq"),
    ]
