# Copyright (C) 2021 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later


"""
CVE checker for libxml2

References:
http://www.cvedetails.com/vulnerability-list/vendor_id-1962/product_id-3311/Xmlsoft-Libxml2.html

RSS feed: http://www.cvedetails.com/vulnerability-feed.php?vendor_id=1962&product_id=3311&version_id=&orderby=2&cvssscoremin=0
"""
import re

from cve_bin_tool.checkers import Checker


class Xml2Checker(Checker):
    CONTAINS_PATTERNS = [
        r"Internal error, xmlCopyCharMultiByte 0x%X out of bound",
        r"xmlNewElementContent : name != NULL !",
        r"xmlRelaxNG: include %s has a define %s but not the included grammar",
    ]
    FILENAME_PATTERNS = [r"libxml2.so."]
    VERSION_PATTERNS = []
    VENDOR_PRODUCT = [("xmlsoft", "libxml2")]

    @staticmethod
    def guess_xml2_version(lines):
        """Guesses the xml2 version from the file contents"""
        new_guess = ""
        pattern1 = re.compile(r"/libxml2-([0-9]+\.[0-9]+\.[0-9]+)/")
        pattern2 = re.compile(r"\\libxml2-([0-9]+\.[0-9]+\.[0-9]+)\\")
        # fedora 29 string looks like libxml2.so.2.9.8-2.9.8-4.fc29.x86_64.debug
        pattern3 = re.compile(r"libxml2.so.([0-9]+\.[0-9]+\.[0-9]+)")

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
            if line == "20901":
                new_guess = "2.9.1"
            if line == "20902":
                new_guess = "2.9.2"
            if line == "20903":
                new_guess = "2.9.3"
            if line == "20904":
                new_guess = "2.9.4"

            match = pattern3.search(line)
            if match:
                new_guess2 = match.group(1).strip()
                if len(new_guess2) > len(new_guess):
                    new_guess = new_guess2
        return new_guess

    def get_version(self, lines, filename):
        version_info = super().get_version(lines, filename)
        if version_info:
            version_info["version"] = self.guess_xml2_version(lines)
        return version_info
