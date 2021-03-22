# Copyright (C) 2021 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later

mapping_test_data = [
    {
        "product": "libpng",
        "version": "2.0.1",
        "version_strings": [
            "libpng error: %s, offset=%d",
            "libpng version 2.0.1 -",
            "libpng version ",
        ],
    }
]
package_test_data = [
    {
        "url": "https://archives.fedoraproject.org/pub/archive/fedora/linux/releases/30/Everything/x86_64/os/Packages/l/",
        "package_name": "libpng-1.6.36-1.fc30.x86_64.rpm",
        "product": "libpng",
        "version": "1.6.36",
    },
    {
        "url": "http://mirror.centos.org/centos/7/os/x86_64/Packages/",
        "package_name": "libpng-1.5.13-8.el7.x86_64.rpm",
        "product": "libpng",
        "version": "1.5.13",
    },
]
