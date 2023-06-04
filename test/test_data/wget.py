# Copyright (C) 2022 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later

mapping_test_data = [
    {
        "product": "wget",
        "version": "1.21.1",
        "version_strings": ["wget-1.21.1"],
    }
]
package_test_data = [
    {
        "url": "http://mirror.stream.centos.org/9-stream/AppStream/aarch64/os/Packages/",
        "package_name": "wget-1.21.1-7.el9.aarch64.rpm",
        "product": "wget",
        "version": "1.21.1",
    },
    {
        "url": "http://ftp.de.debian.org/debian/pool/main/w/wget/",
        "package_name": "wget_1.20.1-1.1_amd64.deb",
        "product": "wget",
        "version": "1.20.1",
    },
]
