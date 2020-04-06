#!/usr/bin/python3

"""
CVE checker for postgresql

https://www.cvedetails.com/product/575/Postgresql-Postgresql.html?vendor_id=336

"""
import os
from ..util import regex_find


def get_version(lines, filename):
    """returns version information for postgresql as found in a given file.
    The version info is returned as a tuple:
        [modulename, is_or_contains, version]

    modulename will be postgresql if postgresql is found (and blank otherwise)
    is_or_contains indicates if the file is a copy of postgresql or contains one
    version gives the actual version number

    VPkg: postgresql, postgresql
    """
    regex = [r"PostgreSQL ([0-9]+\.[0-9]+\.[0-9]+)"]
    version_info = dict()
    version = regex_find(lines, *regex)

    if "psql" in filename:
        version_info["is_or_contains"] = "is"
        version_info["modulename"] = "postgresql"
        version_info["version"] = version
        return version_info

    if version != "UNKNOWN" and "is_or_contains" not in version_info:
        version_info["is_or_contains"] = "contains"
        version_info["modulename"] = "postgresql"
        version_info["version"] = version
        return version_info
    return {}
