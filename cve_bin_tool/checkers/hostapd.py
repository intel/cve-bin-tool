# Copyright (C) 2021 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later


"""
CVE checker for hostapd

https://www.cvedetails.com/product/22495/W1.fi-Hostapd.html?vendor_id=12005

"""
from cve_bin_tool.checkers import Checker


class HostapdChecker(Checker):
    # FIXME: fix contains pattern
    CONTAINS_PATTERNS = []
    FILENAME_PATTERNS = [r"hostapd"]
    VERSION_PATTERNS = [r"hostapd v([0-9]+\.[0-9]+)"]
    VENDOR_PRODUCT = [("w1.fi", "hostapd")]
