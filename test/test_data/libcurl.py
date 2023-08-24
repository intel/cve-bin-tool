# Copyright (C) 2023 Orange
# SPDX-License-Identifier: GPL-3.0-or-later

mapping_test_data = [
    {"product": "libcurl", "version": "7.34.0", "version_strings": ["libcurl 7.34.0"]},
    {"product": "libcurl", "version": "7.34.0", "version_strings": ["libcurl-7.34.0"]},
    {"product": "libcurl", "version": "7.34.0", "version_strings": ["libcurl/7.34.0"]},
]
package_test_data = [
    {
        "url": "http://ftp.br.debian.org/debian/pool/main/c/curl/",
        "package_name": "libcurl3-gnutls_7.64.0-4+deb10u2_amd64.deb",
        "product": "libcurl",
        "version": "7.64.0",
    },
    {
        "url": "http://mirror.centos.org/centos/7/os/x86_64/Packages/",
        "package_name": "libcurl-7.29.0-59.el7.x86_64.rpm",
        "product": "libcurl",
        "version": "7.29.0",
    },
    {
        "url": "https://archives.fedoraproject.org/pub/archive/fedora/linux/releases/30/Everything/x86_64/os/Packages/l/",
        "package_name": "libcurl-7.64.0-6.fc30.x86_64.rpm",
        "product": "libcurl",
        "version": "7.64.0",
    },
    {
        "url": "https://downloads.openwrt.org/releases/packages-19.07/x86_64/base/",
        "package_name": "libcurl4_7.66.0-3_x86_64.ipk",
        "product": "libcurl",
        "version": "7.66.0",
    },
]
