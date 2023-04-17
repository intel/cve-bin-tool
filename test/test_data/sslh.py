# Copyright (C) 2023 Orange
# SPDX-License-Identifier: GPL-3.0-or-later

mapping_test_data = [
    {"product": "sslh", "version": "1.16", "version_strings": ["sslh 1.16"]},
    {"product": "sslh", "version": "1.20", "version_strings": ["sslh v1.20"]},
    {"product": "sslh", "version": "1.22c", "version_strings": ["sslh-1.22c"]},
]
package_test_data = [
    {
        "url": "http://rpmfind.net/linux/opensuse/ports/aarch64/tumbleweed/repo/oss/aarch64/",
        "package_name": "sslh-1.22c-2.3.aarch64.rpm",
        "product": "sslh",
        "version": "1.22c",
    },
    {
        "url": "http://ftp.fr.debian.org/debian/pool/main/s/sslh/",
        "package_name": "sslh_1.16-2_amd64.deb",
        "product": "sslh",
        "version": "1.16",
    },
    {
        "url": "https://downloads.openwrt.org/releases/packages-19.07/x86_64/packages/",
        "package_name": "sslh_v1.20-2_x86_64.ipk",
        "product": "sslh",
        "version": "1.20",
    },
]
