# Copyright (C) 2021 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later


"""
CVE checker for wpa_supplicant

https://www.cvedetails.com/product/29296/W1.fi-Wpa-Supplicant.html?vendor_id=12005

"""
from cve_bin_tool.checkers import Checker


class WpaSupplicantChecker(Checker):
    CONTAINS_PATTERNS = [
        r"wpa_supplicant couldn't remove this interface",
        r"wpa_supplicant knows nothing about this interface",
    ]
    FILENAME_PATTERNS = [r"wpa_supplicant"]
    VERSION_PATTERNS = [r"wpa_supplicant v([0-9]+\.[0-9]+)"]
    VENDOR_PRODUCT = [("w1.fi", "wpa_supplicant")]
