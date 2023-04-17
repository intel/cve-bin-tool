# Copyright (C) 2021 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later

mapping_test_data = [
    {
        "product": "libarchive",
        "version": "3.2.0",
        "version_strings": ["libarchive 3.2.0"],
    }
]
package_test_data = [
    {
        "url": "https://kojipkgs.fedoraproject.org/packages/libarchive/3.3.3/1.fc28/x86_64/",
        "package_name": "libarchive-3.3.3-1.fc28.x86_64.rpm",
        "product": "libarchive",
        "version": "3.3.3",
    },
    {
        "url": "http://mirror.centos.org/centos/7/os/x86_64/Packages/",
        "package_name": "libarchive-3.1.2-14.el7_7.x86_64.rpm",
        "product": "libarchive",
        "version": "3.1.2",
    },
    {
        "url": "http://ftp.br.debian.org/debian/pool/main/liba/libarchive/",
        "package_name": "libarchive13_3.4.3-2+b1_amd64.deb",
        "product": "libarchive",
        "version": "3.4.3",
    },
    {
        "url": "https://ftp.netbsd.org/pub/pkgsrc/packages/NetBSD/amd64/8.2/All/",
        "package_name": "libarchive-3.4.3.tgz",
        "product": "libarchive",
        "version": "3.4.3",
    },
    {
        "url": "https://downloads.openwrt.org/releases/packages-19.07/x86_64/packages/",
        "package_name": "libarchive_3.4.2-1_x86_64.ipk",
        "product": "libarchive",
        "version": "3.4.2",
    },
]
