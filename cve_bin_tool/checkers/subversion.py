# Copyright (C) 2021 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later


"""
CVE checker for subversion CLI
References:
https://subversion.apache.org/
https://www.cvedetails.com/vulnerability-list/vendor_id-2120/product_id-3608/Subversion-Subversion.html
"""
from cve_bin_tool.checkers import Checker


class SubversionChecker(Checker):
    CONTAINS_PATTERNS = [
        r"Working copy locked; if no other Subversion client is currently using the working copy, try running 'svn cleanup' without the --remove",
        r"Working copy locked; try running 'svn cleanup' on the root of the working copy ('%s') instead.",
    ]
    FILENAME_PATTERNS = [
        r"subversion",
        r"svn",
        r"libapache2-svn",
        r"libsvn-dev",
        r"svnadmin",
        r"svnauthz",
        r"svnauthz-validate",
        r"svnbench",
        r"svndumpfilter",
        r"svnfsfs",
        r"svnlook",
        r"svnmucc",
        r"svnrdump",
        r"svnserve",
        r"svnsync",
        r"svnversion",
    ]
    VERSION_PATTERNS = [
        r"subversion-([0-9]+\.[0-9]+\.[0-9]+)",
    ]
    VENDOR_PRODUCT = [("subversion", "subversion"), ("apache", "subversion")]
