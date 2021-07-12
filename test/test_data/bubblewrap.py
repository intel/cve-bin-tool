# Copyright (C) 2021 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later

mapping_test_data = [
    {
        "product": "bubblewrap",
        "version": "0.4.1",
        "version_strings": ["bubblewrap 0.4.1"],
    },
    {
        "product": "bubblewrap",
        "version": "0.4.0",
        "version_strings": ["bubblewrap 0.4.0"],
    },
]
package_test_data = [
    {
        "url": "http://archive.ubuntu.com/ubuntu/pool/main/b/bubblewrap/",
        "package_name": "bubblewrap_0.4.1-3_amd64.deb",
        "product": "bubblewrap",
        "version": "0.4.1",
    },
    {
        "url": "http://mirror.centos.org/centos/8/BaseOS/aarch64/os/Packages/",
        "package_name": "bubblewrap-0.4.0-1.el8.aarch64.rpm",
        "product": "bubblewrap",
        "version": "0.4.0",
    },
]
