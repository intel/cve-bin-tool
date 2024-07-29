# Copyright (C) 2021 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later

mapping_test_data = [
    {
        "product": "binutils",
        "version": "2.31.1",
        "version_strings": [
            "Using the --size-sort and --undefined-only options together",
            "(GNU Binutils for Ubuntu) 2.31.1",
            "Auxiliary filter for shared object symbol table",
        ],
    }
]
package_test_data = [
    {
        "url": "http://security.ubuntu.com/ubuntu/pool/main/b/binutils/",
        "package_name": "binutils_2.26.1-1ubuntu1~16.04.8_amd64.deb",
        "product": "binutils",
        "version": "2.26.1",
    },
    {
        "url": "http://mirror.centos.org/centos/7/os/x86_64/Packages/",
        "package_name": "binutils-2.27-44.base.el7.x86_64.rpm",
        "product": "binutils",
        "version": "2.27",
        "other_products": ["zlib"],
    },
]
