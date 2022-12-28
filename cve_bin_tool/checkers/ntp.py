# Copyright (C) 2021 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later

"""
CVE checker for ntp

References:
https://www.cvedetails.com/product/3682/?q=NTP

"""
from cve_bin_tool.checkers import Checker


class NtpChecker(Checker):
    CONTAINS_PATTERNS = [r"With high-traffic NTP servers, this can occur if the"]
    FILENAME_PATTERNS = [r"ntp"]
    VERSION_PATTERNS = [
        r"ntp(?:d|date|dx|q) ([0-9]+\.[0-9]+\.[0-9]+p[0-9]+)",
    ]
    VENDOR_PRODUCT = [("ntp", "ntp")]
