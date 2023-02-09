# Copyright (C) 2021 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later


"""
CVE checker for kerberos (CLI/library)

References:
https://www.cvedetails.com/product/12666/MIT-Kerberos-5.html?vendor_id=42
"""
from cve_bin_tool.checkers import Checker


class KerberosChecker(Checker):
    CONTAINS_PATTERNS = [r"KRB5_BRAND: "]
    FILENAME_PATTERNS = [r"kerberos"]
    VERSION_PATTERNS = [
        r"KRB5_BRAND: krb5-(\d+\.\d+\.?\d?)-final",
        r"kerberos 5[_-][apl-]*(1+\.[0-9]+(\.[0-9]+)*)",
    ]
    VENDOR_PRODUCT = [("mit", "kerberos_5")]
