#!/usr/bin/env python3
"""
CVE checker for GnuTLS
References:
https://www.cvedetails.com/vulnerability-list/vendor_id-72/product_id-4433/GNU-Gnutls.html
"""
import os
from ..util import regex_find


def get_version(lines, filename):
    """
    returns version information for gnutls found in given file.
    Verfies using the tools gnutls-cli
    Verifies using the libraries libgnutls.so and libgnutls-dane.so

    VPkg: gnu, gnutls
    VPkg: gnutls, gnutls
    """
    regex = [r"gnutls-cli ([0-9]+\.[0-9]+\.[0-9]+)"]

    for modulename, binary_names in (
        {
            "gnutls-serv": ["gnutls-serv"],
            "gnutls-cli": ["gnutls-cli", "libgnutls.so", "libgnutls-dane.so"],
        }
    ).items():
        for check in binary_names:
            if check in os.path.split(filename)[-1]:
                return {
                    "is_or_contains": "is",
                    "modulename": modulename,
                    "version": regex_find(lines, *regex),
                }

    return {}
