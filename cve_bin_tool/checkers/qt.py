#!/usr/bin/python3

"""
CVE checker for qt

https://www.cvedetails.com/product/10758/QT-QT.html?vendor_id=6363
https://www.cvedetails.com/product/24410/Digia-QT.html?vendor_id=12593

"""
from . import Checker


class QtChecker(Checker):
    CONTAINS_PATTERNS = []
    FILENAME_PATTERNS = [
        r"libqt-mt.so",
        r"libQtTest.so",
    ]
    VERSION_PATTERNS = [
        r"Qt ([0-9]+\.[0-9]+\.[0-9]+)",
        r"QTest library ([0-9]+\.[0-9]+\.[0-9]+)",
    ]
    VENDOR_PRODUCT = [("qt", "qt"), ("digia", "qt")]
