# Copyright (C) 2023 Orange
# SPDX-License-Identifier: GPL-3.0-or-later

mapping_test_data = [
    {"product": "dmidecode", "version": "3.5", "version_strings": ["3.5\ndmidecode"]},
    {"product": "dmidecode", "version": "3.0", "version_strings": ["3.0\n# dmidecode"]},
]
package_test_data = [
    {
        "url": "http://rpmfind.net/linux/opensuse/tumbleweed/repo/oss/x86_64/",
        "package_name": "dmidecode-3.5-2.1.x86_64.rpm",
        "product": "dmidecode",
        "version": "3.5",
    },
    {
        "url": "http://ftp.fr.debian.org/debian/pool/main/d/dmidecode/",
        "package_name": "dmidecode_3.0-4_amd64.deb",
        "product": "dmidecode",
        "version": "3.0",
    },
    {
        "url": "https://downloads.openwrt.org/releases/packages-19.07/x86_64/packages/",
        "package_name": "dmidecode_3.2-1_x86_64.ipk",
        "product": "dmidecode",
        "version": "3.2",
    },
]
