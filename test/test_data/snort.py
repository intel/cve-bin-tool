# Copyright (C) 2022 Orange
# SPDX-License-Identifier: GPL-3.0-or-later

mapping_test_data = [
    {"product": "snort", "version": "3.1.43.0", "version_strings": ["snort-3.1.43.0"]},
    {
        "product": "snort",
        "version": "2.9.7.0",
        "version_strings": ["Snort Version 2.9.7.0"],
    },
]
package_test_data = [
    {
        "url": "http://rpmfind.net/linux/openmandriva/cooker/repository/aarch64/unsupported/release/",
        "package_name": "snort-3.1.43.0-1-omv4090.aarch64.rpm",
        "product": "snort",
        "version": "3.1.43.0",
    },
    {
        "url": "http://rpmfind.net/linux/openmandriva/cooker/repository/x86_64/unsupported/release/",
        "package_name": "snort-3.1.43.0-1-omv4090.x86_64.rpm",
        "product": "snort",
        "version": "3.1.43.0",
    },
    {
        "url": "http://ftp.fr.debian.org/debian/pool/main/s/snort/",
        "package_name": "snort_2.9.7.0-5_arm64.deb",
        "product": "snort",
        "version": "2.9.7.0",
    },
    {
        "url": "http://ftp.fr.debian.org/debian/pool/main/s/snort/",
        "package_name": "snort_2.9.15.1-5_amd64.deb",
        "product": "snort",
        "version": "2.9.15.1",
    },
    {
        "url": "https://downloads.openwrt.org/releases/packages-19.07/x86_64/packages/",
        "package_name": "snort_2.9.11.1-8_x86_64.ipk",
        "product": "snort",
        "version": "2.9.11.1",
    },
    {
        "url": "https://downloads.openwrt.org/releases/packages-19.07/x86_64/packages/",
        "package_name": "snort3_3.1.0.0-3_x86_64.ipk",
        "product": "snort",
        "version": "3.1.0.0",
    },
]
