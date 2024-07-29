# Copyright (C) 2023 Orange
# SPDX-License-Identifier: GPL-3.0-or-later


"""
CVE checker for tesseract

https://www.cvedetails.com/product/62309/Tesseract-Project-Tesseract.html?vendor_id=21055
https://www.cvedetails.com/product/97901/Tesseract-Ocr-Project-Tesseract-Ocr.html?vendor_id=24900

"""
from __future__ import annotations

from cve_bin_tool.checkers import Checker


class TesseractChecker(Checker):
    CONTAINS_PATTERNS: list[str] = []
    FILENAME_PATTERNS: list[str] = []
    VERSION_PATTERNS = [r"tesseract ([0-9]+\.[0-9]+\.[0-9]+)"]
    VENDOR_PRODUCT = [
        ("tesseract_project", "tesseract"),
        ("tesseract_ocr_project", "tesseract_ocr"),
    ]
