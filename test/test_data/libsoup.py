# Copyright (C) 2021 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later

mapping_test_data = [
    {
        "product": "libsoup",
        "version": "2.70.0",
        "version_strings": ["libsoup/2.70.0"],
    },
    {
        "product": "libsoup",
        "version": "2.62.3",
        "version_strings": ["libsoup/2.62.3"],
    },
]
package_test_data = [
    {
        "url": "https://download-ib01.fedoraproject.org/pub/fedora/linux/releases/32/Everything/aarch64/os/Packages/l/",
        "package_name": "libsoup-2.70.0-1.fc32.aarch64.rpm",
        "product": "libsoup",
        "version": "2.70.0",
    },
    {
        "url": "http://mirror.centos.org/centos/8/BaseOS/aarch64/os/Packages/",
        "package_name": "libsoup-2.62.3-2.el8.aarch64.rpm",
        "product": "libsoup",
        "version": "2.62.3",
    },
]
