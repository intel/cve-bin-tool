# Copyright (C) 2022 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later

mapping_test_data = [
    {
        "product": "libseccomp",
        "version": "2.3.1",
        "version_strings": ["libseccomp.so.2.3.1"],
    },
    {
        "product": "libseccomp",
        "version": "2.5.0",
        "version_strings": ["libseccomp.so.2.5.0"],
    },
]
package_test_data = [
    {
        "url": "http://mirror.centos.org/centos/7/os/x86_64/Packages/",
        "package_name": "libseccomp-2.3.1-4.el7.x86_64.rpm",
        "product": "libseccomp",
        "version": "2.3.1",
    },
    {
        "url": "https://download-ib01.fedoraproject.org/pub/fedora/linux/releases/34/Everything/x86_64/os/Packages/l/",
        "package_name": "libseccomp-2.5.0-4.fc34.x86_64.rpm",
        "product": "libseccomp",
        "version": "2.5.0",
    },
]
