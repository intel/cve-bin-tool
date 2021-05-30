# Copyright (C) 2021 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later


"""
CVE checker for libsndfile

https://www.cvedetails.com/product/36889/Libsndfile-Project-Libsndfile.html?vendor_id=16294

"""
from cve_bin_tool.checkers import Checker


class LibsndfileChecker(Checker):
    CONTAINS_PATTERNS = [
        r"This version of libsndfile was compiled without Ogg/Speex support.",
        r"No error defined for this error number. This is a bug in libsndfile.",
        r"NULL SF_INFO pointer passed to libsndfile.",
        r"MATLAB 5.0 MAT-file, written by libsndfile-\d+\.\d+\.\d+,",
    ]
    FILENAME_PATTERNS = [r"libsndfile.so"]
    VERSION_PATTERNS = [r"libsndfile-(\d+\.\d+\.\d+)"]
    VENDOR_PRODUCT = [("libsndfile_project", "libsndfile")]
