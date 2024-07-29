# Copyright (C) 2023 Orange
# SPDX-License-Identifier: GPL-3.0-or-later

mapping_test_data = [
    {
        "product": "linux_kernel",
        "version": "3.16.0",
        "version_strings": ["vermagic=3.16.0"],
    },
    {
        "product": "linux_kernel",
        "version": "4.4.50",
        "version_strings": [
            "4.4.50 (buildbot@builds-02.infra.lede-project.org) #0 SMP"
        ],
    },
]
package_test_data = [
    {
        "url": "https://kojipkgs.fedoraproject.org/packages/kernel/2.6.18/1.2798.fc6/x86_64/",
        "package_name": "kernel-2.6.18-1.2798.fc6.x86_64.rpm",
        "product": "linux_kernel",
        "version": "2.6.18",
    },
    {
        "url": "http://ftp.fr.debian.org/debian/pool/main/l/linux/",
        "package_name": "linux-image-3.16.0-6-586_3.16.56-1+deb8u1_i386.deb",
        "product": "linux_kernel",
        "version": "3.16.0",
    },
    {
        "url": "http://ftp.fr.debian.org/debian/pool/main/l/linux/",
        "package_name": "linux-image-5.10.0-21-s390x_5.10.162-1_s390x.deb",
        "product": "linux_kernel",
        "version": "5.10.0",
    },
    {
        "url": "https://downloads.openwrt.org/releases/17.01.0/targets/x86/generic/",
        "package_name": "lede-17.01.0-r3205-59508e3-x86-generic-vmlinuz",
        "product": "linux_kernel",
        "version": "4.4.50",
    },
    {
        "url": "https://downloads.openwrt.org/releases/22.03.3/targets/archs38/generic/",
        "package_name": "openwrt-22.03.3-archs38-generic-uImage",
        "product": "linux_kernel",
        "version": "5.10.161",
        "other_products": ["binutils"],
    },
]
