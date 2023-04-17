# Copyright (C) 2021 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later

mapping_test_data = [
    {
        "product": "zlib",
        "version": "1.2.2",
        "version_strings": ["deflate 1.2.2 Copyright 1995-2005 Jean-loup Gailly"],
    }
]
package_test_data = [
    {
        "url": "https://kojipkgs.fedoraproject.org/packages/zlib/1.2.11/23.fc33/aarch64/",
        "package_name": "zlib-1.2.11-23.fc33.aarch64.rpm",
        "product": "zlib",
        "version": "1.2.11",
    },
    {
        "url": "http://mirror.centos.org/centos/7/os/x86_64/Packages/",
        "package_name": "zlib-1.2.7-18.el7.x86_64.rpm",
        "product": "zlib",
        "version": "1.2.7",
    },
    {
        "url": "http://archive.ubuntu.com/ubuntu/pool/main/z/zlib/",
        "package_name": "zlib1g_1.2.8.dfsg-2ubuntu4_amd64.deb",
        "product": "zlib",
        "version": "1.2.8",
    },
]
