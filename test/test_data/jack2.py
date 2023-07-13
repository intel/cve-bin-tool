# Copyright (C) 2022 Orange
# SPDX-License-Identifier: GPL-3.0-or-later

mapping_test_data = [
    {"product": "jack2", "version": "1.9.21", "version_strings": ["jackdmp 1.9.21"]}
]
package_test_data = [
    {
        "url": "http://rpmfind.net/linux/opensuse/ports/aarch64/tumbleweed/repo/oss/aarch64/",
        "package_name": "jack-1.9.21-1.4.aarch64.rpm",
        "product": "jack2",
        "version": "1.9.21",
    },
    {
        "url": "http://rpmfind.net/linux/opensuse/ports/armv6hl/tumbleweed/repo/oss/armv6hl/",
        "package_name": "jack-1.9.21-1.4.armv6hl.rpm",
        "product": "jack2",
        "version": "1.9.21",
    },
    {
        "url": "http://ftp.fr.debian.org/debian/pool/main/j/jackd2/",
        "package_name": "jackd2_1.9.12~dfsg-2_amd64.deb",
        "product": "jack2",
        "version": "1.9.12",
    },
]
