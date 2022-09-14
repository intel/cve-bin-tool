# Copyright (C) 2021 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later

"""
CVE checker for liblas

https://www.cvedetails.com/product/51704/Liblas-Liblas.html?vendor_id=19562

"""
from cve_bin_tool.checkers import Checker


class LiblasChecker(Checker):
    CONTAINS_PATTERNS = [
        r"N5boost6detail17sp_counted_impl_pIN6liblas5PointEEE",
        r"detail::liblas::read_n<T> input stream is not readable",
        # Alternate optional contains patterns,
        # see https://github.com/intel/cve-bin-tool/tree/main/cve_bin_tool/checkers#helper-script for more details
        # r"N5boost6detail17sp_counted_impl_pIN6liblas6detail10ReaderImplEEE",
        # r"liblas::detail::ReadeVLRData_str: array index out of range",
    ]
    FILENAME_PATTERNS = [r"liblas"]
    VERSION_PATTERNS = [
        r"libLAS ([01]+\.[0-9]+(\.[0-9]+)?)",
    ]
    VENDOR_PRODUCT = [("liblas", "liblas")]
