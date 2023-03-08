# Copyright (C) 2022 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later


"""
CVE checker for jackson-databind:

https://www.cvedetails.com/vulnerability-list/vendor_id-15866/product_id-42991/Fasterxml-Jackson-databind.html
"""
from cve_bin_tool.checkers import Checker


class JacksondatabindChecker(Checker):
    CONTAINS_PATTERNS = [
        r"<description>General data-binding functionality for Jackson: works on core streaming API</description>",
        r"<url>http://github.com/FasterXML/jackson-databind</url>",
    ]
    FILENAME_PATTERNS = [r"jackson-databind(-[0-9]+\.[0-9]+\.[0-9]+(.[0-9]+)?)?.jar"]
    VERSION_PATTERNS = [
        r"<tag>jackson-databind-([0-9]+\.[0-9]+\.[0-9]+(.[0-9]+)?)</tag>"
    ]
    VENDOR_PRODUCT = [("fasterxml", "jackson-databind")]
