# Copyright (C) 2021 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later


"""
CVE checker for gcc

https://www.cvedetails.com/vulnerability-list/vendor_id-72/product_id-960/GNU-GCC.html

"""
from cve_bin_tool.checkers import Checker


class GccChecker(Checker):
    # NOTE: find version string for debian packages
    CONTAINS_PATTERNS = [
        r"Do not predefine system-specific and GCC-specific macros\.",
        r"Dump detailed information on GCC's internal representation of source code locations\.",
        # Alternate optional contains patterns,
        # see https://github.com/intel/cve-bin-tool/tree/main/cve_bin_tool/checkers#helper-script for more details
        # r"GCC is not configured to support %s as offload target",
        # r"IPA lattices after constant propagation, before gcc_unreachable:",
        # r"Record gcc command line switches in DWARF DW_AT_producer\.",
        # r"Record gcc command line switches in the object file\.",
        # r"Warn about packed bit-fields whose offset changed in GCC [0-9]\.[0-9]\.",
        # r"binary constants are a C\+\+14 feature or GCC extension",
        # r"fixed-point constants are a GCC extension",
        # r"gcc driver version %s %sexecuting gcc version %s",
        # r"offset of packed bit-field %qD has changed in GCC [0-9]\.[0-9]",
        # r"style of line directive is a GCC extension",
        # r"suffix for double constant is a GCC extension",
    ]
    FILENAME_PATTTERN = [r"gcc"]
    VERSION_PATTERNS = [
        r"GCC: \(GNU\) ([0-9]+\.[0-9]+(\.[0-9]+)?)",
        # r"gcc ([0-9]+\.[0-9]+(\.[0-9]+)?)",  # does not return correct version number on some packages
    ]
    VENDOR_PRODUCT = [("gnu", "gcc")]
