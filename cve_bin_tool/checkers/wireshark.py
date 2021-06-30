# Copyright (C) 2021 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later


"""
CVE checker for wireshark

https://www.cvedetails.com/product/8292/Wireshark-Wireshark.html?vendor_id=4861

"""
from cve_bin_tool.checkers import Checker


class WiresharkChecker(Checker):
    CONTAINS_PATTERNS = []
    FILENAME_PATTERNS = [r"rawshark"]
    VERSION_PATTERNS = [r"Wireshark ([0-9]+\.[0-9]+\.[0-9]+)"]
    VENDOR_PRODUCT = [("wireshark", "wireshark")]
