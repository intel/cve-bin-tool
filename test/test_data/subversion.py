# Copyright (C) 2021 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later

mapping_test_data = [
    {
        "product": "subversion",
        "version": "1.13.0",
        "version_strings": [
            r"subversion-1.13.0",
            r"Working copy locked; if no other Subversion client is currently using the working copy, try running 'svn cleanup' without the --remove",
            r"Working copy locked; try running 'svn cleanup' on the root of the working copy ('%s') instead.",
        ],
    }
]
package_test_data = [
    {
        "url": "http://ports.ubuntu.com/pool/main/s/subversion/",
        "package_name": "subversion_1.9.3-2ubuntu1_arm64.deb",
        "product": "subversion",
        "version": "1.9.3",
    }
]
