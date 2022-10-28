# Copyright (C) 2021 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later

mapping_test_data = [
    {"product": "gnutls", "version": "2.1.6", "version_strings": ["gnutls-cli 2.1.6"]},
    {
        "product": "gnutls",
        "version": "2.3.11",
        "version_strings": ["gnutls-serv 2.3.11"],
    },
    {"product": "gnutls", "version": "3.6.15", "version_strings": ["GnuTLS 3.6.15"]},
]
package_test_data = [
    {
        "url": "http://mirror.centos.org/centos/7/os/x86_64/Packages/",
        "package_name": "gnutls-utils-3.3.29-9.el7_6.x86_64.rpm",
        "product": "gnutls",
        "version": "3.3.29",
    },
    {
        "url": "http://rpmfind.net/linux/fedora/linux/development/rawhide/Everything/aarch64/os/Packages/g/",
        "package_name": "gnutls-3.7.8-8.fc38.aarch64.rpm",
        "product": "gnutls",
        "version": "3.7.8",
    },
    {
        "url": "http://archive.ubuntu.com/ubuntu/pool/universe/g/gnutls28/",
        "package_name": "gnutls-bin_3.4.10-4ubuntu1.7_amd64.deb",
        "product": "gnutls",
        "version": "3.4.10",
    },
    {
        "url": "https://downloads.openwrt.org/releases/packages-19.07/x86_64/packages/",
        "package_name": "libgnutls_3.6.15-2_x86_64.ipk",
        "product": "gnutls",
        "version": "3.6.15",
    },
]
