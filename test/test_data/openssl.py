# Copyright (C) 2021 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later

mapping_test_data = [
    {
        "product": "openssl",
        "version": "1.1.1d",
        "version_strings": ["part of OpenSSL 1.1.1d ", "OpenSSL 1.1.1d "],
    },
    {
        "product": "openssl",
        "version": "1.0.2g",
        "version_strings": ["part of OpenSSL 1.0.2g ", "OpenSSL 1.0.2g "],
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
        "url": "https://files.pythonhosted.org/packages/ba/91/84a29d6a27fd6dfc21f475704c4d2053d58ed7a4033c2b0ce1b4ca4d03d9/",
        "package_name": "cryptography-3.0-cp35-abi3-manylinux2010_x86_64.whl",
        "product": "openssl",
        "version": "1.1.1g",
    },
]
