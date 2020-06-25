# pylint: disable=invalid-name
#!/usr/bin/python3

"""
CVE checker for libxerces

References:
http://www.cvedetails.com/vulnerability-list/vendor_id-45/product_id-4103/Apache-Xerces-c-.html

RSS feed: http://www.cvedetails.com/vulnerability-feed.php?vendor_id=45&product_id=4103&version_id=&orderby=2&cvssscoremin=0
"""
from . import Checker


class XercesChecker(Checker):
    CONTAINS_PATTERNS = [r"xerces-c-src_"]
    FILENAME_PATTERNS = [r"libxerces-c.so", r"libxerces-c-3.1.so"]
    VERSION_PATTERNS = [
        r"\/xerces-c-src_([0-9]+_[0-9]+_[0-9]+)\/",
        r"xercesc_([0-9]+\_[0-9]+):",
    ]
    VENDOR_PRODUCT = [("apache", "xerces-c")]
