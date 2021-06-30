# Copyright (C) 2021 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later

"""
CVE checker for Python
References:
https://www.cvedetails.com/vulnerability-list/vendor_id-10210/product_id-18230/Python-Python.html


"""
import re

from cve_bin_tool.checkers import Checker
from cve_bin_tool.util import regex_find


class PythonChecker(Checker):
    CONTAINS_PATTERNS = [
        r"Fatal Python error: unable to decode the command line argument",
        r"Internal error in the Python interpreter",
        r"CPython",
    ]
    FILENAME_PATTERNS = [r"python"]
    VERSION_PATTERNS = [r"python([23]+\.[0-9])"]
    VENDOR_PRODUCT = [("python_software_foundation", "python"), ("python", "python")]

    def get_version(self, lines, filename):
        # we will try to find python3+ as well as python2+

        # currently regex will probably find a single string "lib/python3.6"
        # where 3.6 is the version similarly "lib/python2.7" where 2.7 is the version
        version_info = super().get_version(lines, filename)

        # we will check if the guess returned some version probably 3.6 or 2.7 in our example
        # return version_info
        if "version" in version_info and version_info["version"] != "UNKNOWN":

            # we will update our regex to something more precise 3.6.d
            # where d is unknown and we will find d. which will return 3.6.9 or some other version
            version_pattern = [
                rf"([{version_info['version'][0]}]+\.[{version_info['version'][2]}]+\.[0-9]+)"
            ]
            version_regex = list(map(re.compile, version_pattern))
            new_version = regex_find(lines, version_regex)

            # we will return this result
            version_info["version"] = new_version

        # else guess was unknown so we update our regex
        elif version_info:
            version_pattern = [
                r"version: ([23]+\.[0-9]+\.[0-9])+",
                r"Python ([23]+\.[0-9]+\.[0-9])+",
            ]
            version_regex = list(map(re.compile, version_pattern))
            new_version = regex_find(lines, version_regex)

            version_info["version"] = new_version
        return version_info
