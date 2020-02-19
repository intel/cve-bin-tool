#!/usr/bin/python3

"""
CVE checker for libdb (berkeley db)
CVE list: https://www.cvedetails.com/vulnerability-list/vendor_id-93/product_id-32070/Oracle-Berkeley-Db.html
"""
import re
from ..util import regex_find


def guess_contains_libdb(lines):
    """Tries to determine if a file includes libdb
    """
    signatures = [
        "BDB1568 Berkeley DB library does not support DB_REGISTER on this system",
        "BDB1507 Thread died in Berkeley DB library",
        "Berkeley DB ",
    ]
    for line in lines:
        for signature in signatures:
            if signature in line:
                return True
    return False


def get_version(lines, filename):
    """returns version information for libdb as found in a given file.
    The version info is returned as a tuple:
        [modulename, is_or_contains, version]
    modulename will be libdb if libdb is found (and blank otherwise)
    is_or_contains idicates if the file is a copy of libdb or contains one
    version gives the actual version number
    VPkg: oracle, berkeley_db
    """
    regex = [
        r"Berkeley DB ([0-9]+\.[0-9]+\.[0-9]+):",  # short version as backup. we mostly want the long below.
        r"Berkeley DB .+, library version ([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+):",
    ]
    version_info = dict()
    if "libdb-" in filename:
        version_info["is_or_contains"] = "is"
    elif guess_contains_libdb(lines):
        version_info["is_or_contains"] = "contains"

    if "is_or_contains" in version_info:
        version_info["modulename"] = "libdb"
        version_info["version"] = regex_find(lines, *regex)

    return version_info
