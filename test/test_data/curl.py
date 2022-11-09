# Copyright (C) 2021 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later

mapping_test_data = [
    {"product": "curl", "version": "7.34.0", "version_strings": ["curl 7.34.0"]},
    {"product": "curl", "version": "7.34.0", "version_strings": ["curl-7.34.0"]},
    {"product": "curl", "version": "7.34.0", "version_strings": ["curl/7.34.0"]},
]
package_test_data = [
    {
        "url": "https://archives.fedoraproject.org/pub/archive/fedora/linux/releases/20/Everything/x86_64/os/Packages/c/",
        "package_name": "curl-7.32.0-3.fc20.x86_64.rpm",
        "product": "curl",
        "version": "7.32.0",
    },
    {
        "url": "https://ftp.netbsd.org/pub/pkgsrc/packages/NetBSD/aarch64/9.1/All/",
        "package_name": "curl-7.77.0.tgz",
        "product": "curl",
        "version": "7.77.0",
    },
    {
        "url": "http://ftp.br.debian.org/debian/pool/main/c/curl/",
        "package_name": "curl_7.52.1-5+deb9u10_amd64.deb",
        "product": "curl",
        "version": "7.52.1",
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
]
