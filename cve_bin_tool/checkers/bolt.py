# Copyright (C) 2021 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later


"""
CVE checker for bolt

https://www.cvedetails.com/product/64828/Boltcms-Bolt.html?vendor_id=21391

"""
from cve_bin_tool.checkers import Checker


class BoltChecker(Checker):
    CONTAINS_PATTERNS = [
        r"State of the ForcePower setting of the bolt daemon.",
        r"The generation of the Thunderbolt controller associated",
        r"The maximum generation of any of Thunderbolt controller",
    ]
    FILENAME_PATTERNS = [r"boltd"]
    VERSION_PATTERNS = [r"bolt ([0-9]+\.[0-9]+(\.[0-9])?)"]
    VENDOR_PRODUCT = [("boltcms", "bolt")]
