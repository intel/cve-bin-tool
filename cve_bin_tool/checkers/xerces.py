# pylint: disable=invalid-name
#!/usr/bin/python3

"""
CVE checker for libxerces

References:
http://www.cvedetails.com/vulnerability-list/vendor_id-45/product_id-4103/Apache-Xerces-c-.html

RSS feed: http://www.cvedetails.com/vulnerability-feed.php?vendor_id=45&product_id=4103&version_id=&orderby=2&cvssscoremin=0
"""
from ..util import regex_find


def guess_contains_xerces(lines):
    """Tries to determine if a file includes xerces
    """
    for line in lines:
        if "xerces-c-src_" in line:
            return 1
    return 0


def get_version(lines, filename):
    """returns version information for xerces as found in a given file.
    The version info is returned as a tuple:
        [modulename, is_or_contains, version]

    modulename will be xerces if xerces is found (and blank otherwise)
    is_or_contains idicates if the file is a copy of xerces or contains one
    version gives the actual version number

    VPkg: apache, xerces-c
    """
    regex = [r"\/xerces-c-src_([0-9]+_[0-9]+_[0-9]+)\/", r"xercesc_([0-9]+\_[0-9]+):"]

    version_info = dict()
    if "libxerces-c.so" in filename or "libxerces-c-3.1.so" in filename:
        version_info["is_or_contains"] = "is"
    elif guess_contains_xerces(lines):
        version_info["is_or_contains"] = "contains"

    if "is_or_contains" in version_info:
        version_info["modulename"] = "xerces"
        version_info["version"] = regex_find(lines, *regex)

    return version_info
