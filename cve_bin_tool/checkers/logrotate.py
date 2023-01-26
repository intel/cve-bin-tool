# Copyright (C) 2021 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later


"""
CVE checker for logrotate

References: https://www.cvedetails.com/product/20629/?q=Logrotate
https://www.cvedetails.com/product/115897/Logrotate-Project-Logrotate.html?vendor_id=27259

"""
from cve_bin_tool.checkers import Checker


class LogrotateChecker(Checker):
    CONTAINS_PATTERNS = [
        r"Set \"su\" directive in config file to tell logrotate which user/group should be used for rotation",
        r"WARNING: logrotate in debug mode does nothing except printing debug messages!  Consider using verbose mode \(-v\) instead if this is not what you want.",
    ]
    FILENAME_PATTERNS = [r"logrotate"]
    VERSION_PATTERNS = [
        r"logrotate ([0-9]+\.[0-9]+\.[0-9]+) - Copyright \(C\) 1995-2001 Red Hat, Inc."
    ]
    VENDOR_PRODUCT = [("gentoo", "logrotate"), ("logrotate_project", "logrotate")]
