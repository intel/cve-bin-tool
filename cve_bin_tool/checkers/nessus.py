#!/usr/bin/python3

"""
CVE checker for nessus

References:
https://www.cvedetails.com/vulnerability-list/vendor_id-12865/product_id-27428/Tenable-Nessus.html
"""
from ..util import regex_find


def guess_contains_nessus(lines):
    """Tries to determine if a file includes nessus
    """
    for line in lines:
        if "you have deleted older versions nessus libraries from your system" in line:
            return 1
        if "server_info_nessusd_version" in line:
            return 1
        if "nessuslib_version" in line:
            return 1
        if "nessus_lib_version" in line:
            return 1

    return 0


def get_version(lines, filename):
    """returns version information for nessus as found in a given file.
    The version info is returned as a tuple:
        [modulename, is_or_contains, version]

    modulename will be nessus if nessus is found (and blank otherwise)
    is_or_contains idicates if the file is a copy of nessus or contains one
    version gives the actual version number

    VPkg: tenable, nessus
    """
    # string found in rpmfind's's pkg
    regex = [r"Nessus ([0-9]+\.[0-9]+\.[0-9]+)"]
    # strings found in fedora's pkg
    regex1 = [r"libnessus.so.([0-9]+\.[0-9]+\.[0-9]+)"]
    version_info = dict()
    if "libnessus" in filename:
        version_info["is_or_contains"] = "is"
    elif guess_contains_nessus(lines):
        version_info["is_or_contains"] = "contains"

    if "is_or_contains" in version_info:
        version_info["modulename"] = "nessus"
        version_info["version"] = regex_find(lines, *regex)
        # tries alternate regex
        if version_info["version"] == "UNKNOWN":
            version_info["version"] = regex_find(lines, *regex1)

    return version_info
