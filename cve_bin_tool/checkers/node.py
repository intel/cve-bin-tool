# Copyright (C) 2021 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later


"""
CVE checker for node.js

References:
http://www.cvedetails.com/vulnerability-list/vendor_id-12113/Nodejs.html

RSS feed: http://www.cvedetails.com/vulnerability-feed.php?vendor_id=12113&product_id=0&version_id=&orderby=3&cvssscoremin=0
"""
from cve_bin_tool.checkers import Checker


class NodeChecker(Checker):
    CONTAINS_PATTERNS = [
        r"https://nodejs.org/download/release/v",
        r"(0) == (uv_async_init(uv_default_loop(), &dispatch_debug_messages_async, DispatchDebugMessagesAsyncCallback))",
        r"Documentation can be found at http://nodejs.org/",
    ]
    FILENAME_PATTERNS = [r"bin/node"]
    VERSION_PATTERNS = [
        r"https\:\/\/nodejs.org\/download\/release\/v([0-9]+\.[0-9]+\.[0-9]+)\/",
        r"(?:\r?\n|\/)node v([0-9]+\.[0-9]+\.[0-9]+)",
    ]
    VENDOR_PRODUCT = [("nodejs", "node.js")]
