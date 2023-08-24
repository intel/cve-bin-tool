# Copyright (C) 2021 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later


"""
CVE checker for mysql CLI
References:
https://www.mysql.com/
https://www.cvedetails.com/vulnerability-list/vendor_id-93/product_id-21801/Oracle-Mysql.html
"""
from cve_bin_tool.checkers import Checker


class MysqlChecker(Checker):
    CONTAINS_PATTERNS = [
        r"To buy MySQL Enterprise support, training, or other products, visit:",
    ]
    FILENAME_PATTERNS = [
        r"mysql",
        r"mysqladmin",
        r"mysql-community",
        r"mysql-client",
        r"mysql-client-core",
        r"mysql-server",
        r"mysql-server-core",
        r"mysql-community-client",
        r"mysql-bench",
        r"dovecot-mysql",
    ]
    VERSION_PATTERNS = [r"mysql\-[0-9]+\.[0-9]+\-([0-9]+\.[0-9]+\.[0-9]+)"]
    VENDOR_PRODUCT = [("oracle", "mysql"), ("mysql", "mysql")]
