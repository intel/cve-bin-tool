# Copyright (C) 2021 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later

mapping_test_data = [
    {
        "product": "libssh2",
        "version": "1.8.0",
        "version_strings": ["SSH-2.0-libssh2_1.8.0"],
    },
    {
        "product": "libssh2",
        "version": "1.9.0",
        "version_strings": ["SSH-2.0-libssh2_1.9.0"],
    },
]
package_test_data = [
    {
        "url": "https://download-ib01.fedoraproject.org/pub/epel/8/Everything/aarch64/Packages/l/",
        "package_name": "libssh2-1.9.0-5.el8.aarch64.rpm",
        "product": "libssh2",
        "version": "1.9.0",
    },
    {
        "url": "http://mirror.centos.org/altarch/7/os/aarch64/Packages/",
        "package_name": "libssh2-1.8.0-4.el7.aarch64.rpm",
        "product": "libssh2",
        "version": "1.8.0",
    },
]
