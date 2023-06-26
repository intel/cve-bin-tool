# Copyright (C) 2023 Orange
# SPDX-License-Identifier: GPL-3.0-or-later

mapping_test_data = [
    {"product": "coreutils", "version": "8.30", "version_strings": ["coreutils-8.30"]},
    {"product": "coreutils", "version": "8.30", "version_strings": ["coreutils\n8.30"]},
]
package_test_data = [
    {
        "url": "http://rpmfind.net/linux/opensuse/ports/i586/tumbleweed/repo/oss/i586/",
        "package_name": "coreutils-9.3-1.2.i586.rpm",
        "product": "coreutils",
        "version": "9.3",
    },
    {
        "url": "http://ftp.fr.debian.org/debian/pool/main/c/coreutils/",
        "package_name": "coreutils_8.30-3_amd64.deb",
        "product": "coreutils",
        "version": "8.30",
    },
    {
        "url": "https://downloads.openwrt.org/releases/packages-19.07/x86_64/packages/",
        "package_name": "coreutils-base64_8.30-2_x86_64.ipk",
        "product": "coreutils",
        "version": "8.30",
    },
]
