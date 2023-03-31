# Copyright (C) 2021 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later

mapping_test_data = [
    {
        "product": "kexec-tools",
        "version": "2.0.21",
        "version_strings": ["kexec-tools 2.0.21"],
    },
    {
        "product": "kexec-tools",
        "version": "2.0.16",
        "version_strings": ["kexec-tools 2.0.16"],
    },
]
package_test_data = [
    {
        "url": "https://download-ib01.fedoraproject.org/pub/fedora/linux/releases/34/Everything/aarch64/os/Packages/k/",
        "package_name": "kexec-tools-2.0.21-5.fc34.aarch64.rpm",
        "product": "kexec-tools",
        "version": "2.0.21",
        "other_products": ["gcc"],
    },
    {
        "url": "http://archive.ubuntu.com/ubuntu/pool/main/k/kexec-tools/",
        "package_name": "kexec-tools_2.0.16-1ubuntu1_amd64.deb",
        "product": "kexec-tools",
        "version": "2.0.16",
    },
    {
        "url": "https://downloads.openwrt.org/releases/packages-19.07/x86_64/base/",
        "package_name": "kexec_2.0.16-2_x86_64.ipk",
        "product": "kexec-tools",
        "version": "2.0.16",
    },
]
