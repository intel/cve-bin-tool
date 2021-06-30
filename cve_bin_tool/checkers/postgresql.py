# Copyright (C) 2021 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later


"""
CVE checker for postgresql

https://www.cvedetails.com/product/575/Postgresql-Postgresql.html?vendor_id=336

"""
from cve_bin_tool.checkers import Checker


class PostgresqlChecker(Checker):
    # FIXME: fix contains pattern
    CONTAINS_PATTERNS = []
    FILENAME_PATTERNS = [r"psql"]
    VERSION_PATTERNS = [r"PostgreSQL ([0-9]+\.[0-9]+\.[0-9]+)"]
    VENDOR_PRODUCT = [("postgresql", "postgresql")]
