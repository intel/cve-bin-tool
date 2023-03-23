# Copyright (C) 2021 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later


"""
CVE checker for icu CLI

References:
https://www.cvedetails.com/vulnerability-list/vendor_id-17477/Icu-project.html
https://www.cvedetails.com/product/101097/Unicode-International-Components-For-Unicode.html?vendor_id=21486
"""
from cve_bin_tool.checkers import Checker


class IcuChecker(Checker):
    CONTAINS_PATTERNS = [
        r"-i or --icudatadir       directory for locating any needed intermediate data files,",
        r"-j or --write-java       write a Java ListResourceBundle for ICU4J, followed by optional encoding",
        r"failed to load root collator \(ucadata.icu\) - %s",
        r"is about 300kB larger than the ucadata-implicithan\.icu version\.",
        r"the ucadata-unihan\.icu version of the collation root data",
    ]
    FILENAME_PATTERNS = [r"genrb", r"uconv"]
    VERSION_PATTERNS = [
        r"icu(?:-|/)([0-9]+\.[0-9]+(\.[0-9]+)?)",
        r"ICU ([0-9]+\.[0-9]+(\.[0-9]+)?)",
    ]
    VENDOR_PRODUCT = [
        ("icu-project", "international_components_for_unicode"),
        ("unicode", "international_components_for_unicode"),
    ]
