#!/usr/bin/python3

"""
CVE checker for rsyslog
https://www.cvedetails.com/product/15708/Rsyslog-Rsyslog.html?vendor_id=3361
"""
import os
from ..util import regex_find


def get_version(lines, filename):
    """returns version information for rsyslog as found in a given file.
    The version info is returned as a tuple:
        [modulename, is_or_contains, version]
    modulename will be rsyslog if rsyslog is found (and blank otherwise)
    is_or_contains indicates if the file is a copy of rsyslog or contains one
    version gives the actual version number
    VPkg: rsyslog, rsyslog
    """
    regex = [r"rsyslog ([0-9]+\.[0-9]+\.[0-9]+)"]
    version_info = dict()
    version = regex_find(lines, *regex)

    if "rsyslogd" in filename:
        version_info["is_or_contains"] = "is"
        version_info["modulename"] = "rsyslog"
        version_info["version"] = version
        return version_info

    if version != "UNKNOWN" and "is_or_contains" not in version_info:
        version_info["is_or_contains"] = "contains"
        version_info["modulename"] = "rsyslog"
        version_info["version"] = version
        return version_info
    return {}
