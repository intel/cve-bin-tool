#!/usr/bin/python3

"""
CVE checker for openssl

References:
https://www.openssl.org/news/vulnerabilities.html
http://www.cvedetails.com/vulnerability-list/vendor_id-217/product_id-383/Openssl-Openssl.html

RSS feed: http://www.cvedetails.com/vulnerability-feed.php?vendor_id=217&product_id=383&version_id=&orderby=3&cvssscoremin=0
"""
import re

def openssl_version_from_content(lines):
    """
    Guess a version based on regex of the content for openssl
    """
    new_guess = ""
    pattern1 = re.compile(r"part of OpenSSL ([01]+\.[0-9]+\.[0-9]+[a-z]*) ")
    pattern2 = re.compile(r"OpenSSL ([01]+\.[0-9]+\.[0-9]+[a-z]*) ")

    for line in lines:
        match = pattern1.search(line)
        if match:
            new_guess2 = match.group(1).strip()
            if len(new_guess2) > len(new_guess):
                new_guess = new_guess2
        match = pattern2.search(line)
        if match:
            new_guess2 = match.group(1).strip()
            if len(new_guess2) > len(new_guess):
                new_guess = new_guess2

    return new_guess

def contains_openssl(lines):
    """
    Determine if the binary contains openssl
    """
    for line in lines:
        if "part of OpenSSL" in line:
            return 1
        if "openssl.cnf" in line:
            return 1
        if "-DOPENSSL_" in line:
            return 1
    return 0

def get_version(lines, filename):
    """
    Get the version and return it for openssl

    VPkg: openssl, openssl
    """
    version_info = dict()
    if ("libssl.so." in filename) or ("libcrypto.so" in filename):
        version_info["is_or_contains"] = "is"
    elif contains_openssl(lines):
        version_info["is_or_contains"] = "contains"

    if "is_or_contains" in version_info:
        version_info["modulename"] = "openssl"
        version_info["version"] = openssl_version_from_content(lines)

    return version_info
