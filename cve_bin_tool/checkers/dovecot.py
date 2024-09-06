# Copyright (C) 2021 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later


"""
CVE checker for dovecot

https://www.cvedetails.com/product/10948/Dovecot-Dovecot.html?vendor_id=6485

"""
from cve_bin_tool.checkers import Checker


class DovecotChecker(Checker):
    CONTAINS_PATTERNS = [
        r"BUG: Authentication client %u requested invalid authentication mechanism %s \(DOVECOT-TOKEN required\)",
        r"DOVECOT_SRAND is not available in non-debug builds",
        # Alternate optional contains patterns,
        # see https://github.com/intel/cve-bin-tool/tree/main/cve_bin_tool/checkers#helper-script for more details
        # r"Dovecot is already running with PID %s \(read from %s\)",
        # r"Dovecot is already running\? Socket already exists: %s",
        # r"Must be started by dovecot master process",
        # r"Usage: dovecot \[-F\] \[-c <config file>\] \[-p\] \[-n\] \[-a\] \[--help\] \[--version\]",
    ]
    FILENAME_PATTERNS = [r"dovecot"]
    VERSION_PATTERNS = [
        r"Dovecot v([0-9]+\.[0-9]+\.[0-9]+(\.[0-9]+)?)",
        r"DOVECOT_VERSION=([0-9]+\.[0-9]+\.[0-9]+(\.[0-9]+)?)",
    ]
    VENDOR_PRODUCT = [("dovecot", "dovecot")]
