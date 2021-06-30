# Copyright (C) 2021 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later

mapping_test_data = [
    {"product": "gnutls", "version": "2.1.6", "version_strings": ["gnutls-cli 2.1.6"]},
    {
        "product": "gnutls",
        "version": "2.3.11",
        "version_strings": ["gnutls-serv 2.3.11"],
    },
]
package_test_data = [
    {
        "url": "http://mirror.centos.org/centos/7/os/x86_64/Packages/",
        "package_name": "gnutls-utils-3.3.29-9.el7_6.x86_64.rpm",
        "product": "gnutls",
        "version": "3.3.29",
    },
    {
        "url": "http://archive.ubuntu.com/ubuntu/pool/universe/g/gnutls28/",
        "package_name": "gnutls-bin_3.4.10-4ubuntu1.7_amd64.deb",
        "product": "gnutls",
        "version": "3.4.10",
    },
]
