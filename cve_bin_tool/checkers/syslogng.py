# Copyright (C) 2021 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later


"""
CVE checker for Syslog-ng

References:
https://www.cvedetails.com/vulnerability-list/vendor_id-644/product_id-20465/Balabit-Syslog-ng.html
RSS feed: http://www.cvedetails.com/vulnerability-feed.php?vendor_id=644&product_id=20465&version_id=0&orderby=3&cvssscoremin=0

"""
from cve_bin_tool.checkers import Checker


class SyslogngChecker(Checker):
    CONTAINS_PATTERNS = [
        r"Set syslog-ng control socket",
        r"Stop syslog-ng process",
    ]
    FILENAME_PATTERNS = [r"syslog-ng"]
    VERSION_PATTERNS = [
        r"syslog-ng-([0-9]+\.[0-9]+\.[0-9]+)",
        r"syslog-ng ([0-9]+\.[0-9]+\.[0-9]+)",
    ]
    VENDOR_PRODUCT = [("balabit", "syslog-ng"), ("oneidentity", "syslog-ng")]
