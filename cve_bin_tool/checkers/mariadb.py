# Copyright (C) 2021 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later


"""
CVE checker for mariadb CLI

References:
https://github.com/MariaDB/server
https://www.cvedetails.com/vulnerability-list/vendor_id-12010/product_id-22503/Mariadb-Mariadb.html


"""
from cve_bin_tool.checkers import Checker


class MariadbChecker(Checker):
    CONTAINS_PATTERNS = [
        r"Oracle, MariaDB Corporation Ab and others.",
        r"General information about MariaDB can be found at\nhttp://mariadb.org",
        r"Welcome to the MariaDB monitor.",
        r"MariaDB virtual IO plugin for socket communication",
    ]
    FILENAME_PATTERNS = [
        r"mariadb",
        r"mariadb-client",
        r"mariadb_config",
        r"mariadb-client-core",
        r"mariadb-test",
        r"mariadb-test-data",
        r"odbc-mariadb",
        r"libmariadb-dev",
        r"libmariadb-dev-compat",
        r"libmariadb-java",
        r"libmariadbclient-dev",
        r"mariadb-backup",
        r"mariadb-plugin",
    ]
    VERSION_PATTERNS = [
        r"([0-9]+\.[0-9]+\.[0-9]+)-MariaDB",
        r"([0-9]+\.[0-9]+\.[0-9]+)\r?\nMariaDB",
    ]
    VENDOR_PRODUCT = [("mariadb", "mariadb")]
