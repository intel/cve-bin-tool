#!/usr/bin/python3

"""
CVE checker for libexpat

References:
http://www.cvedetails.com/vulnerability-list/vendor_id-12037/product_id-22545/Libexpat-Expat.html
http://www.cvedetails.com/vulnerability-list/vendor_id-16735/product_id-39003/Libexpat-Project-Libexpat.html
https://github.com/libexpat/libexpat/blob/master/expat/Changes

RSS feeds:
http://www.cvedetails.com/vulnerability-feed.php?vendor_id=12682&product_id=0&version_id=0&orderby=3&cvssscoremin=0
http://www.cvedetails.com/vulnerability-feed.php?vendor_id=16735&product_id=0&version_id=0&orderby=3&cvssscoremin=0

Easiest way to check CVEs is currently the Changes.txt file.  You can pinpoint the CVEs using grep as follows:
grep 'Release\|CVE' Changes.txt

Which will give you output like...

Release 2.2.5 Tue October 31 2017
Release 2.2.4 Sat August 19 2017
Release 2.2.3 Wed August 2 2017
             #82  CVE-2017-11742 -- Windows: Fix DLL hijacking vulnerability
Release 2.2.2 Wed July 12 2017
Release 2.2.1 Sat June 17 2017
                  CVE-2017-9233 -- External entity infinite loop DoS
(etc.)

"""
import re

def guess_expat_version_from_content(lines):
    """Guesses the expat version from the file contents
    """
    new_guess = ""
    pattern1 = re.compile(r"expat_([012]+\.[0-9]+\.[0-9]+)")
    #pattern2 = re.compile(r"\/expat-([012]+\.[0-9]+\.[0-9]+)-r[0-9]\/")

    for line in lines:
        match = pattern1.search(line)
        if match:
            new_guess2 = match.group(1).strip()
            if len(new_guess2) > len(new_guess):
                new_guess = new_guess2

    return new_guess

def guess_contains_expat(lines):
    """Tries to determine if a file includes expat
    """
    for line in lines:
        if "reserved prefix (xml) must not be undeclared or bound to another namespace name" in line:
            return 1
        if "cannot change setting once parsing has begun" in line:
            return 1
        if "requested feature requires XML_DTD support in Expat" in line:
            return 1
    return 0

def get_version(lines, filename):
    """returns version information for expat as found in a given file.
    The version info is returned as a tuple:
        [modulename, is_or_contains, version]

    modulename will be expat if expat is found (and blank otherwise)
    is_or_contains idicates if the file is a copy of expat or contains one
    version gives the actual version number

    VPkg: libexpat, expat
    VPkg: libexpat_project, libexpat
    """
    version_info = dict()
    if "libexpat.so." in filename:
        version_info["is_or_contains"] = "is"
    elif guess_contains_expat(lines):
        version_info["is_or_contains"] = "contains"

    if "is_or_contains" in version_info:
        version_info["modulename"] = "expat"
        version_info["version"] = guess_expat_version_from_content(lines)

    return version_info

