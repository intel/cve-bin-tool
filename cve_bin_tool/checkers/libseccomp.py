# Copyright (C) 2022 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later

"""
CVE checker for libseccomp

https://www.cvedetails.com/vulnerability-list/vendor_id-19760/product_id-53398/Libseccomp-Project-Libseccomp.html
"""
from cve_bin_tool.checkers import Checker


class LibseccompChecker(Checker):
    CONTAINS_PATTERNS = []
    FILENAME_PATTERNS = [r"libseccomp"]
    VERSION_PATTERNS = [
        r"libseccomp.so.([0-9]+\.[0-9]+\.[0-9]+)"
    ]  # patterns like this aren't ideal
    VENDOR_PRODUCT = [("libseccomp_project", "libseccomp")]
