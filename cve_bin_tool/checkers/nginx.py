#!/usr/bin/python3

"""
CVE checker for nginx

References:
https://www.cvedetails.com/vulnerability-list/vendor_id-10048/product_id-17956/Nginx-Nginx.html

RSS feed: http://www.cvedetails.com/vulnerability-feed.php?vendor_id=10048&product_id=17956&version_id=0&orderby=3&cvssscoremin=0

"""
from ..util import regex_find


def guess_contains_nginx(lines):
    """Tries to determine if a file includes nginx
    """
    for line in lines:
        if "NGINX environment variable" in line:
            return 1
        if "nginx was built with Session Tickets support" in line:
            return 1

    return 0


def get_version(lines, filename):
    """returns version information for nginx as found in a given file.
    The version info is returned as a tuple:
        [modulename, is_or_contains, version]

    modulename will be nginx if nginx is found (and blank otherwise)
    is_or_contains idicates if the file is a copy of nginx or contains one
    version gives the actual version number

    VPkg: nginx, nginx
    """
    regex = [r"nginx/([0-9]+\.[0-9]+\.[0-9]+)"]
    version_info = dict()
    if "nginx" in filename:
        version_info["is_or_contains"] = "is"
    elif guess_contains_nginx(lines):
        version_info["is_or_contains"] = "contains"

    if "is_or_contains" in version_info:
        version_info["modulename"] = "nginx"
        version_info["version"] = regex_find(lines, *regex)

    return version_info
