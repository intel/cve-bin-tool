# Copyright (C) 2021 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later

mapping_test_data = [
    {
        "product": "libsolv",
        "version": "0.6.34",
        "version_strings": ["libsolv-0.6.34"],
    },
    {
        "product": "libsolv",
        "version": "0.7.16",
        "version_strings": ["libsolv.so.1-0.7.16"],
    },
    {
        "product": "libsolv",
        "version": "0.7.17",
        "version_strings": ["libsolv.so.1-0.7.17"],
    },
    {
        "product": "libsolv",
        "version": "0.6.35",
        "version_strings": ["libsolv/0.6.35"],
    },
]
package_test_data = [
    {
        "url": "http://mirror.centos.org/centos/7/os/x86_64/Packages/",
        "package_name": "libsolv-0.6.34-4.el7.x86_64.rpm",
        "product": "libsolv",
        "version": "0.6.34",
    },
    {
        "url": "http://mirror.centos.org/centos/8-stream/BaseOS/x86_64/os/Packages/",
        "package_name": "libsolv-0.7.16-2.el8.x86_64.rpm",
        "product": "libsolv",
        "version": "0.7.16",
    },
    {
        "url": "https://download-ib01.fedoraproject.org/pub/fedora/linux/releases/34/Everything/x86_64/os/Packages/l/",
        "package_name": "libsolv-0.7.17-3.fc34.x86_64.rpm",
        "product": "libsolv",
        "version": "0.7.17",
    },
]
