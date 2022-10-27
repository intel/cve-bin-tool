# Copyright (C) 2021 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later

mapping_test_data = [
    {
        "product": "bzip2",
        "version": "1.0.2",
        "version_strings": ["bzip2-1.0.2", "bzip2recover 1.0.2"],
    },
    {
        "product": "bzip2",
        "version": "1.0.6",
        "version_strings": ["1.0.6, 6-Sept-2010\nbzip2/libbzip2"],
    },
]
package_test_data = [
    {
        "url": "https://kojipkgs.fedoraproject.org/packages/bzip2/1.0.4/10.fc7/x86_64/",
        "package_name": "bzip2-1.0.4-10.fc7.x86_64.rpm",
        "product": "bzip2",
        "version": "1.0.4",
    },
    {
        "url": "http://mirror.centos.org/centos/7/os/x86_64/Packages/",
        "package_name": "bzip2-1.0.6-13.el7.x86_64.rpm",
        "product": "bzip2",
        "version": "1.0.6",
    },
    {
        "url": "https://ftp.netbsd.org/pub/pkgsrc/packages/NetBSD/aarch64/9.1/All/",
        "package_name": "bzip2-1.0.8.tgz",
        "product": "bzip2",
        "version": "1.0.8",
    },
    {
        "url": "http://archive.ubuntu.com/ubuntu/pool/main/b/bzip2/",
        "package_name": "bzip2_1.0.8-4ubuntu3_amd64.deb",
        "product": "bzip2",
        "version": "1.0.8",
    },
    {
        "url": "https://downloads.openwrt.org/releases/packages-19.07/x86_64/base/",
        "package_name": "libbz2-1.0_1.0.8-1_x86_64.ipk",
        "product": "bzip2",
        "version": "1.0.8",
    },
]
