# Copyright (C) 2021 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later

mapping_test_data = [
    {
        "product": "cryptsetup",
        "version": "2.3.6",
        "version_strings": [
            "Legacy offline reencryption already in-progress. Use cryptsetup-reencrypt utility.",
            "Only LUKS2 format is currently supported. Please use cryptsetup-reencrypt tool for LUKS1.",
            "cryptsetup 2.3.6",
        ],
    },
    {
        "product": "cryptsetup",
        "version": "2.0.3",
        "version_strings": [
            "Legacy offline reencryption already in-progress. Use cryptsetup-reencrypt utility.",
            "Only LUKS2 format is currently supported. Please use cryptsetup-reencrypt tool for LUKS1.",
            "cryptsetup 2.0.3",
        ],
    },
]
package_test_data = [
    {
        "url": "https://download-ib01.fedoraproject.org/pub/fedora/linux/development/rawhide/Everything/aarch64/os/Packages/c/",
        "package_name": "cryptsetup-2.3.6-1.fc35.aarch64.rpm",
        "product": "cryptsetup",
        "version": "2.3.6",
    },
    {
        "url": "http://mirror.centos.org/altarch/7/os/aarch64/Packages/",
        "package_name": "cryptsetup-2.0.3-6.el7.aarch64.rpm",
        "product": "cryptsetup",
        "version": "2.0.3",
    },
    {
        "url": "http://ftp.fr.debian.org/debian/pool/main/c/cryptsetup/",
        "package_name": "libcryptsetup12_2.1.0-5+deb10u2_arm64.deb",
        "product": "cryptsetup",
        "version": "2.1.0",
    },
]
