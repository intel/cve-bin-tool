# Copyright (C) 2021 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later

mapping_test_data = [
    {
        "product": "libsndfile",
        "version": "1.0.25",
        "version_strings": ["libsndfile-1.0.25"],
    }
]
package_test_data = [
    {
        "url": "http://mirror.centos.org/altarch/7/os/aarch64/Packages/",
        "package_name": "libsndfile-1.0.25-12.el7.aarch64.rpm",
        "product": "libsndfile",
        "version": "1.0.25",
    },
    {
        "url": "http://ftp.br.debian.org/debian/pool/main/libs/libsndfile/",
        "package_name": "libsndfile1_1.0.31-2_amd64.deb",
        "product": "libsndfile",
        "version": "1.0.31",
    },
    {
        "url": "https://ftp.netbsd.org/pub/pkgsrc/packages/NetBSD/amd64/8.2/All/",
        "package_name": "libsndfile-1.0.31.tgz",
        "product": "libsndfile",
        "version": "1.0.31",
    },
    {
        "url": "https://downloads.openwrt.org/releases/packages-19.07/x86_64/packages/",
        "package_name": "libsndfile_2019-04-21-25824cb9-1_x86_64.ipk",
        "product": "libsndfile",
        "version": "1.0.29pre1",
    },
]
