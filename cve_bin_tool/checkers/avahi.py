# Copyright (C) 2021 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later


"""
CVE checker for avahi

https://www.cvedetails.com/product/7747/Avahi-Avahi.html?vendor_id=4481

"""
from cve_bin_tool.checkers import Checker


class AvahiChecker(Checker):
    CONTAINS_PATTERNS = []
    FILENAME_PATTERNS = [r"avahi-daemon"]
    VERSION_PATTERNS = [r"avahi[a-zA-Z \r\n'-/.%:-]*([0-9]+\.[0-9]+\.?[0-9]*)"]
    VENDOR_PRODUCT = [("avahi", "avahi")]
