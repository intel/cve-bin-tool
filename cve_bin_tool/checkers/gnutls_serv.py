#!/usr/bin/env python3
"""
CVE checker for GnuTLS
References:
https://www.cvedetails.com/vulnerability-list/vendor_id-72/product_id-4433/GNU-Gnutls.html
"""
from . import Checker


class GnutlsServChecker(Checker):
    # FIXME: fix contains pattern
    CONTAINS_PATTERNS = []
    FILENAME_PATTERNS = ["gnutls-serv"]
    VERSION_PATTERNS = [r"gnutls-serv ([0-9]+\.[0-9]+\.[0-9]+)"]
    VENDOR_PACKAGE = [("gnutls", "gnutls"), ("gnu", "gnutls")]
    MODULE_NAME = "gnutls-serv"
