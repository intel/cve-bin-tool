# Copyright (C) 2021 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later

mapping_test_data = [
    {
        "product": "openssl",
        "version": "1.1.1d",
        "version_strings": [
            "part of OpenSSL 1.1.1d  10 Sep 2019\n%s (Library: %s)",
            "OpenSSL 1.1.1d  10 Sep 2019\n%s (Library: %s)",
        ],
    },
    {
        "product": "openssl",
        "version": "1.0.2g",
        "version_strings": [
            "%s (Library: %s)\npart of OpenSSL 1.0.2g  1 Mar 2016",
            "%s (Library: %s)\nOpenSSL 1.0.2g  1 Mar 2016",
        ],
    },
]
package_test_data = [
    {
        "url": "http://rpmfind.net/linux/mageia/distrib/5/i586/media/core/updates/",
        "package_name": "openssl-1.0.2g-1.1.mga5.i586.rpm",
        "product": "openssl",
        "version": "1.0.2g",
    },
    {
        "url": "http://ftp.de.debian.org/debian/pool/main/o/openssl/",
        "package_name": "openssl_3.0.5-4_amd64.deb",
        "product": "openssl",
        "version": "3.0.5",
    },
    {
        "url": "http://ftp.de.debian.org/debian/pool/main/o/openssl/",
        "package_name": "libssl3_3.1.5-1_arm64.deb",
        "product": "openssl",
        "version": "3.1.5",
    },
    {
        "url": "https://files.pythonhosted.org/packages/ba/91/84a29d6a27fd6dfc21f475704c4d2053d58ed7a4033c2b0ce1b4ca4d03d9/",
        "package_name": "cryptography-3.0-cp35-abi3-manylinux2010_x86_64.whl",
        "product": "openssl",
        "version": "1.1.1g",
        "other_products": ["gcc"],
    },
    {
        "url": "https://downloads.openwrt.org/releases/packages-19.07/x86_64/base/",
        "package_name": "libopenssl1.1_1.1.1n-1_x86_64.ipk",
        "product": "openssl",
        "version": "1.1.1n",
    },
]
