# Copyright (C) 2021 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later

"""
CVE checker for GNUPG

https://www.cvedetails.com/vulnerability-list/vendor_id-4711/product_id-8075/Gnupg-Gnupg.html

"""
from cve_bin_tool.checkers import Checker


class GnupgChecker(Checker):
    CONTAINS_PATTERNS = [
        r"# \(Use \"gpg --import-ownertrust\" to restore them\)",
        r"Comment: Use \"gpg --dearmor\" for unpacking",
        # Alternate optional contains patterns,
        # see https://github.com/intel/cve-bin-tool/tree/main/cve_bin_tool/checkers#helper-script for more details
        # r"standalone revocation - use \"gpg --import\" to apply",
        # r"you can update your preferences with: gpg --edit-key %s updpref save",
    ]
    FILENAME_PATTERNS = [
        "gpg",  # to match gpg, gpg2, gpg1
        # "g13",
    ]
    VERSION_PATTERNS = [
        r"gpg\.conf\-([0-9]+\.[0-9]+\.[0-9]+)",
        # r"(GnuPG) ([0-9]+\.[0-9]+\.[0-9]+)",
        # r"GNU Privacy Guard's OpenPGP server ([0-9]+\.[0-9]+\.[0-9]+) ready",
        # r"GNU Privacy Guard's G13 server ([0-9]+\.[0-9]+\.[0-9]+) ready",
    ]
    VENDOR_PRODUCT = [("gnupg", "gnupg")]
