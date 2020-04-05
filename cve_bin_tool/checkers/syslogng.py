#!/usr/bin/python3

"""
CVE checker for Syslog-ng

References:
https://www.cvedetails.com/vulnerability-list/vendor_id-644/product_id-20465/Balabit-Syslog-ng.html
RSS feed: http://www.cvedetails.com/vulnerability-feed.php?vendor_id=644&product_id=20465&version_id=0&orderby=3&cvssscoremin=0

"""
from ..util import regex_find


def guess_contains_syslogng(lines):
    """Tries to determine if a file includes Syslog-ng
    """
    for line in lines:
        if "Set syslog-ng control socket" in line:
            return 1
        if "Stop syslog-ng process" in line:
            return 1

    return 0


def get_version(lines, filename):
    """returns version information for Syslog-ng as found in a given file.
    The version info is returned as a tuple:
        [modulename, is_or_contains, version]

    modulename will be syslog-ng if Syslog-ng is found (and blank otherwise)
    is_or_contains idicates if the file is a copy of Syslog-ng or contains one
    version gives the actual version number

    VPkg: balabit, syslog-ng
    """
    # string found in arch linux's pkg
    regex = [r"syslog-ng-([0-9]+\.[0-9]+\.[0-9]+)"]
    version_info = dict()
    if "syslog-ng" in filename:
        version_info["is_or_contains"] = "is"
    elif guess_contains_syslogng(lines):
        version_info["is_or_contains"] = "contains"

    if "is_or_contains" in version_info:
        version_info["modulename"] = "syslog-ng"
        version_info["version"] = regex_find(lines, *regex)

    return version_info
