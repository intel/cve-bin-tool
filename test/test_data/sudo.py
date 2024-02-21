# Copyright (C) 2021 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later

mapping_test_data = [
    {
        "product": "sudo",
        "version": "1.9.1",
        "version_strings": [
            r"Sudo Audit Server 1.9.1",
            r"Sudo Sendlog 1.9.1",
            r"sudoers 1.9.1",
            r"subversion-1.13.0",
            r"sudo_debug_exit_str_masked_v1",
            r"sudo_debug_set_active_instance_v1",
            r"sudo_fatal_callback_register_v1",
        ],
    }
]
package_test_data = [
    {
        "url": "http://ports.ubuntu.com/pool/main/s/sudo/",
        "package_name": "sudo_1.9.1-1ubuntu1.1_arm64.deb",
        "product": "sudo",
        "version": "1.9.1",
    },
    {
        "url": "https://ftp.lysator.liu.se/pub/opensuse/ports/aarch64/distribution/leap/15.3/repo/oss/x86_64/",
        "package_name": "sudo-1.9.5p2-1.5.x86_64.rpm",
        "product": "sudo",
        "version": "1.9.5p2",
        "other_products": ["protobuf-c"],
    },
    {
        "url": "http://ftp.fr.debian.org/debian/pool/main/s/sudo/",
        "package_name": "sudo_1.8.10p3-1+deb8u5_amd64.deb",
        "product": "sudo",
        "version": "1.8.10p3",
    },
    {
        "url": "https://downloads.openwrt.org/releases/packages-19.07/x86_64/packages/",
        "package_name": "sudo_1.8.28p1-2_x86_64.ipk",
        "product": "sudo",
        "version": "1.8.28p1",
    },
]
