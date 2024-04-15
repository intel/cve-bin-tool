# Copyright (C) 2021 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later

"""
CVE checker for Python
References:
https://www.cvedetails.com/vulnerability-list/vendor_id-10210/product_id-18230/Python-Python.html


"""
from cve_bin_tool.checkers import Checker


class PythonChecker(Checker):
    CONTAINS_PATTERNS = [
        r"Fatal Python error: unable to decode the command line argument",
        r"Internal error in the Python interpreter",
        r"CPython",
    ]
    FILENAME_PATTERNS = [r"python"]
    VERSION_PATTERNS = [
        r"python(?:[23]+\.[0-9]+)-([23]+\.[0-9]+\.[0-9]+)",
        r"pymalloc_debug\r?\n([23]+\.[0-9]+\.[0-9]+)",
        r"([23]+\.[0-9]+\.[0-9]+)\r?\nPython %s",
        r"([23]+\.[0-9]+\.[0-9]+)\r?\n%\.80s \(%\.80s\) %\.80s",
        r"tags/v([23]+\.[0-9]+\.[0-9]+)\r?\nversion_info",
    ]
    VENDOR_PRODUCT = [("python_software_foundation", "python"), ("python", "python")]
