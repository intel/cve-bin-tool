# Copyright (C) 2021 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later


"""
CVE checker for nginx

References:
https://www.cvedetails.com/vulnerability-list/vendor_id-10048/product_id-17956/Nginx-Nginx.html
https://www.cvedetails.com/product/101578/F5-Nginx.html?vendor_id=315

RSS feed: http://www.cvedetails.com/vulnerability-feed.php?vendor_id=10048&product_id=17956&version_id=0&orderby=3&cvssscoremin=0

"""
from cve_bin_tool.checkers import Checker


class NginxChecker(Checker):
    CONTAINS_PATTERNS = [
        r"NGINX environment variable",
        r"nginx was built with Session Tickets support",
    ]
    FILENAME_PATTERNS = [r"nginx"]
    VERSION_PATTERNS = [r"nginx/([0-9]+\.[0-9]+\.[0-9]+)"]
    VENDOR_PRODUCT = [("f5", "nginx"), ("nginx", "nginx")]
