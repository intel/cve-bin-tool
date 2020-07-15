#!/usr/bin/python3

"""
CVE checker for postgresql

https://www.cvedetails.com/product/575/Postgresql-Postgresql.html?vendor_id=336

"""
from . import Checker


class PostgresqlChecker(Checker):
    # FIXME: fix contains pattern
    CONTAINS_PATTERNS = []
    FILENAME_PATTERNS = [r"psql"]
    VERSION_PATTERNS = [r"PostgreSQL ([0-9]+\.[0-9]+\.[0-9]+)"]
    VENDOR_PRODUCT = [("postgresql", "postgresql")]
