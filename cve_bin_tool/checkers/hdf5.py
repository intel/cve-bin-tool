# Copyright (C) 2021 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later


"""
CVE checker for hdf5

https://www.cvedetails.com/product/35054/Hdfgroup-Hdf5.html?vendor_id=15991

"""
from cve_bin_tool.checkers import Checker


class Hdf5Checker(Checker):
    CONTAINS_PATTERNS = [
        r"### HDF5 metadata cache trace file version 1 ###",
        r"%s'HDF5_DISABLE_VERSION_CHECK' environment variable is set to %d, application will",
        # Alternate optional contains patterns,
        # see https://github.com/intel/cve-bin-tool/tree/main/cve_bin_tool/checkers#helper-script for more details
        # r"The HDF5 header files used to compile this application do not match",
        # r"The HDF5 library version information are not consistent in its source code.",
        # r"This can happen when an application was compiled by one version of HDF5 but",
        # r"file locking disabled on this file system \(use HDF5_USE_FILE_LOCKING environment variable to override\)",
        # r"linked with a different version of static or shared HDF5 library\.",
        # r"the version used by the HDF5 library to which this application is linked\.",
        # r"variable 'HDF5_DISABLE_VERSION_CHECK' to a value of '1'\.",
        # r"variable 'HDF5_DISABLE_VERSION_CHECK' to a value of 1 will suppress",
    ]
    FILENAME_PATTERNS = [r"libhdf5.so."]
    VERSION_PATTERNS = [
        r"HDF5 library version: ([0-9]+\.[0-9]+(\.[0-9]+))",
        r"HDF5 Version: ([0-9]+\.[0-9]+(\.[0-9]+))",
    ]
    VENDOR_PRODUCT = [("hdfgroup", "hdf5")]
