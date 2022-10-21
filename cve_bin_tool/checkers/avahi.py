# Copyright (C) 2021 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later


"""
CVE checker for avahi

https://www.cvedetails.com/product/7747/Avahi-Avahi.html?vendor_id=4481

"""
from cve_bin_tool.checkers import Checker


class AvahiChecker(Checker):
    CONTAINS_PATTERNS = [
        r"avahi_free",
        r"avahi_strerror",
        # Alternate optional contains patterns,
        # see https://github.com/intel/cve-bin-tool/tree/main/cve_bin_tool/checkers#helper-script for more details
        # r"avahi_string_list_free",
        # r"libavahi-common.so.3",
    ]
    FILENAME_PATTERNS = [r"avahi-daemon"]
    VERSION_PATTERNS = [r"avahi[ -]([0-9]+\.[0-9]+\.?[0-9]*)"]
    VENDOR_PRODUCT = [("avahi", "avahi")]
