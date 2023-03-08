# Copyright (C) 2022 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later


"""
CVE checker for Apache HTTP Server

https://www.cvedetails.com/vulnerability-list/vendor_id-45/product_id-66/Apache-Http-Server.html
"""
from cve_bin_tool.checkers import Checker


class ApacheHttpServerChecker(Checker):
    CONTAINS_PATTERNS = [
        r"logs/apache_runtime_status",
        r"httpd not running, trying to start",
        r"-D HTTPD_ROOT=\"/etc/httpd\"",
    ]
    FILENAME_PATTTERN = [r"httpd"]
    VERSION_PATTERNS = [
        r"Apache/([0-9]+\.[0-9]+(\.[0-9]+)?) ",
    ]
    VENDOR_PRODUCT = [("apache", "http_server")]
