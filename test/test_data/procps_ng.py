# Copyright (C) 2022 Orange
# SPDX-License-Identifier: GPL-3.0-or-later

mapping_test_data = [
    {"product": "procps-ng", "version": "4.0.0", "version_strings": ["procps-ng 4.0.0"]}
]
package_test_data = [
    {
        "url": "http://rpmfind.net/linux/openmandriva/cooker/repository/aarch64/main/release/",
        "package_name": "procps-ng-4.0.0-1-omv4090.aarch64.rpm",
        "product": "procps-ng",
        "version": "4.0.0",
    },
    {
        "url": "http://rpmfind.net/linux/openmandriva/cooker/repository/x86_64/main/release/",
        "package_name": "procps-ng-4.0.0-1-omv4090.x86_64.rpm",
        "product": "procps-ng",
        "version": "4.0.0",
    },
    {
        "url": "http://ftp.fr.debian.org/debian/pool/main/p/procps/",
        "package_name": "procps_3.3.12-3+deb9u1_amd64.deb",
        "product": "procps-ng",
        "version": "3.3.12",
    },
    {
        "url": "https://downloads.openwrt.org/releases/packages-19.07/x86_64/packages/",
        "package_name": "procps-ng-free_3.3.15-2_x86_64.ipk",
        "product": "procps-ng",
        "version": "3.3.15",
    },
]
