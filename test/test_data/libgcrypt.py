# Copyright (C) 2021 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later

mapping_test_data = [
    {
        "product": "libgcrypt",
        "version": "1.6.0",
        "version_strings": ["Libgcrypt 1.6.0", "severe error getting random"],
    }
]
package_test_data = [
    {
        "url": "http://mirror.centos.org/centos/7/os/x86_64/Packages/",
        "package_name": "libgcrypt-1.5.3-14.el7.x86_64.rpm",
        "product": "libgcrypt",
        "version": "1.5.3",
    },
    {
        "url": "https://archives.fedoraproject.org/pub/archive/fedora/linux/releases/30/Everything/x86_64/os/Packages/l/",
        "package_name": "libgcrypt-1.8.4-3.fc30.x86_64.rpm",
        "product": "libgcrypt",
        "version": "1.8.4",
    },
]
