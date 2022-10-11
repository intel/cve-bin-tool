# Copyright (C) 2021 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later


"""
CVE checker for openldap

https://www.cvedetails.com/product/755/Openldap-Openldap.html?vendor_id=439

"""
from cve_bin_tool.checkers import Checker


class OpenldapChecker(Checker):
    FILENAME_PATTERNS = [r"ldapsearch"]
    VERSION_PATTERNS = [
        r"ldapsearch ([0-9]+\.[0-9]+\.[0-9]+)",
        r"OpenLDAP: slapd ([0-9]+\.[0-9]+\.[0-9]+)",
    ]
    VENDOR_PRODUCT = [("openldap", "openldap")]
