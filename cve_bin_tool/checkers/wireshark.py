# Copyright (C) 2021 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later


"""
CVE checker for wireshark

https://www.cvedetails.com/product/8292/Wireshark-Wireshark.html?vendor_id=4861

"""
from cve_bin_tool.checkers import Checker


class WiresharkChecker(Checker):
    CONTAINS_PATTERNS = [
        r"'usermod -a -G wireshark _your_username_' as root.",
        r"Are you a member of the 'wireshark' group\? Try running",
    ]
    FILENAME_PATTERNS = [r"rawshark", r"wireshark"]
    VERSION_PATTERNS = [r"Wireshark ([0-9]+\.[0-9]+\.[0-9]+)\."]
    VENDOR_PRODUCT = [("wireshark", "wireshark")]
