# Copyright (C) 2021 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later

mapping_test_data = [
    {
        "product": "libcurl",
        "version": "7.65.0",
        "version_strings": [
            "An unknown option was passed in to libcurl",
            "CLIENT libcurl 7.65.0",
        ],
    }
]
package_test_data = [
    {
        "url": "http://mirror.centos.org/centos/7/os/x86_64/Packages/",
        "package_name": "libcurl-7.29.0-59.el7.x86_64.rpm",
        "product": "libcurl",
        "version": "7.29.0",
    },
    {
        "url": "https://archives.fedoraproject.org/pub/archive/fedora/linux/releases/30/Everything/x86_64/os/Packages/l/",
        "package_name": "libcurl-7.64.0-6.fc30.x86_64.rpm",
        "product": "libcurl",
        "version": "7.64.0",
    },
]
