# Copyright (C) 2021 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later


"""
CVE checker for rsyslog
https://www.cvedetails.com/product/15708/Rsyslog-Rsyslog.html?vendor_id=3361
"""
from cve_bin_tool.checkers import Checker


class RsyslogChecker(Checker):
    CONTAINS_PATTERNS = []
    FILENAME_PATTERNS = [r"rsyslogd"]
    VERSION_PATTERNS = [r"rsyslog ([0-9]+\.[0-9]+\.[0-9]+)"]
    VENDOR_PRODUCT = [("rsyslog", "rsyslog")]
