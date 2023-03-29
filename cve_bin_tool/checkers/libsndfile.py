# Copyright (C) 2021 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later


"""
CVE checker for libsndfile

https://www.cvedetails.com/vulnerability-list/vendor_id-8760/product_id-16957/Mega-nerd-Libsndfile.html
https://www.cvedetails.com/product/36889/Libsndfile-Project-Libsndfile.html?vendor_id=16294

"""
from cve_bin_tool.checkers import Checker


class LibsndfileChecker(Checker):
    CONTAINS_PATTERNS = [
        r"No error defined for this error number. This is a bug in libsndfile.",
        r"NULL SF_INFO pointer passed to libsndfile.",
        # Alternate optional contains patterns,
        # see https://github.com/intel/cve-bin-tool/tree/main/cve_bin_tool/checkers#helper-script for more details
        # r"MATLAB 5.0 MAT-file, written by libsndfile-(\d+\.\d+\.\d+),",
    ]
    FILENAME_PATTERNS = [r"libsndfile.so"]
    VERSION_PATTERNS = [r"libsndfile-(\d+\.\d+\.\d+[a-z0-9]*)\r?\n"]
    VENDOR_PRODUCT = [("libsndfile_project", "libsndfile"), ("mega-nerd", "libsndfile")]
