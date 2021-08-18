# Copyright (C) 2021 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later

"""
CVE checker for libssh2

https://www.cvedetails.com/product/31293/Libssh2-Libssh2.html?vendor_id=15300

"""
from cve_bin_tool.checkers import Checker


class Libssh2Checker(Checker):
    CONTAINS_PATTERNS = [
        r"Invalid descriptor passed to libssh2_poll()",
        r"libssh2_channel_wait_closed() invoked when channel is not in EOF state",
    ]
    FILENAME_PATTERNS = [r"libssh2"]
    VERSION_PATTERNS = [r"SSH-2.0-libssh2_([0-9]+\.[0-9]+\.[0-9]+)"]
    VENDOR_PRODUCT = [("libssh2", "libssh2")]
