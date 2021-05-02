# Copyright (C) 2021 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later


"""
CVE checker for openssl

References:
https://www.openssl.org/news/vulnerabilities.html
http://www.cvedetails.com/vulnerability-list/vendor_id-217/product_id-383/Openssl-Openssl.html

RSS feed: http://www.cvedetails.com/vulnerability-feed.php?vendor_id=217&product_id=383&version_id=&orderby=3&cvssscoremin=0
"""
from cve_bin_tool.checkers import Checker


class OpensslChecker(Checker):
    CONTAINS_PATTERNS = [r"part of OpenSSL", r"openssl.cnf", r"-DOPENSSL_"]
    FILENAME_PATTERNS = [r"libssl.so.", r"libcrypto.so"]
    VERSION_PATTERNS = [
        r"part of OpenSSL ([01]+\.[0-9]+\.[0-9]+[a-z]*) ",
        r"OpenSSL ([01]+\.[0-9]+\.[0-9]+[a-z]*) ",
    ]
    VENDOR_PRODUCT = [("openssl", "openssl")]
