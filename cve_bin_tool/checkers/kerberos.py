#!/usr/bin/python3

"""
CVE checker for kerberos (CLI/library)

References:
https://www.cvedetails.com/vulnerability-list/vendor_id-42/product_id-61/MIT-Kerberos.html
"""
import re
from ..util import regex_find


def guess_krb5_version_from_content(lines):
    """Guesses the krb version from the file contents
    """
    new_guess = ""

    # Library signature looks like "KRB5_BRAND: krb5-1.15.1-final 1.15.1 20170302"
    signatures = [r"KRB5_BRAND: krb5-(\d+\.\d+\.?\d?)-final"]

    new_guess = regex_find(lines, *signatures)
    if new_guess:
        return new_guess

    # CLI signature
    pattern1 = re.compile(r"kerberos 5[_-](appl-)*(1+\.[0-9]+(\.[0-9]+)*)")

    for line in lines:
        match = pattern1.search(line)
        if match:
            print(match.group(0))
            new_guess2 = match.group(0).strip()
            if len(new_guess2) > len(new_guess):
                new_guess = new_guess2

    return new_guess[9:]


def guess_contains_kerberos(lines):
    signatures = ["KRB5_BRAND: "]
    for line in lines:
        for signature in signatures:
            if signature in line:
                return True
    return False


def get_version(lines, filename):
    """returns version information for kerberos as found in a given file.
    The version info is returned as a tuple:
        [modulename, is_or_contains, version]

    modulename will be kerbors if kerberos is found (and blank otherwise)
    is_or_contains idicates if the file is a copy of kerberos or contains one
    version gives the actual version number

    VPkg: mit, kerberos
    """
    version_info = dict()
    if "kerberos" in filename:
        version_info["is_or_contains"] = "is"
    elif guess_contains_kerberos(lines):
        version_info["is_or_contains"] = "contains"

    if "is_or_contains" in version_info:
        version_info["modulename"] = "kerberos"
        version_info["version"] = guess_krb5_version_from_content(lines)

    return version_info
