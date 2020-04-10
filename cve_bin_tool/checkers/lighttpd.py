#!/usr/bin/python3

"""
CVE checker for lighttpd

References:
https://www.cvedetails.com/vulnerability-list/vendor_id-2713/product_id-4762/Lighttpd-Lighttpd.html

RSS feed: http://www.cvedetails.com/vulnerability-feed.php?vendor_id=2713&product_id=4762&version_id=0&orderby=3&cvssscoremin=0

"""
from ..util import regex_find


def guess_contains_lighttpd(lines):
    """Tries to determine if a file includes lighttpd
    """
    for line in lines:
        if "Invalid fds at startup with lighttpd" in line:
            return 1
        if "lighttpd will fail to start up" in line:
            return 1

    return 0


def get_version(lines, filename):
    """returns version information for lighttpd as found in a given file.
    The version info is returned as a tuple:
        [modulename, is_or_contains, version]

    modulename will be lighttpd if lighttpd is found (and blank otherwise)
    is_or_contains idicates if the file is a copy of lighttpd or contains one
    version gives the actual version number

    VPkg: lighttpd, lighttpd
    """
    regex = [r"lighttpd/([0-9]+\.[0-9]+\.[0-9]+)"]
    version_info = dict()
    if "lighttpd" in filename:
        version_info["is_or_contains"] = "is"
    elif guess_contains_lighttpd(lines):
        version_info["is_or_contains"] = "contains"

    if "is_or_contains" in version_info:
        version_info["modulename"] = "lighttpd"
        version_info["version"] = regex_find(lines, *regex)

    return version_info
