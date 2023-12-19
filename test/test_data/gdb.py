# Copyright (C) 2022 Orange
# SPDX-License-Identifier: GPL-3.0-or-later

mapping_test_data = [
    {"product": "gdb", "version": "7.12", "version_strings": ["gdb-7.12"]},
    {"product": "gdb", "version": "8.2.1", "version_strings": ["gdb-8.2.1"]},
]
package_test_data = [
    {
        "url": "http://rpmfind.net/linux/opensuse/ports/aarch64/tumbleweed/repo/oss/aarch64/",
        "package_name": "gdb-12.1-4.1.aarch64.rpm",
        "product": "gdb",
        "version": "12.1",
    },
    {
        "url": "http://ftp.fr.debian.org/debian/pool/main/g/gdb/",
        "package_name": "gdb_7.12-6_amd64.deb",
        "product": "gdb",
        "version": "7.12",
    },
    {
        "url": "http://ftp.fr.debian.org/debian/pool/main/g/gdb/",
        "package_name": "gdb_8.2.1-2+b3_mips64el.deb",
        "product": "gdb",
        "version": "8.2.1",
    },
    {
        "url": "https://downloads.openwrt.org/releases/packages-19.07/x86_64/base/",
        "package_name": "gdb_8.3.1-1_x86_64.ipk",
        "product": "gdb",
        "version": "8.3.1",
        "other_products": ["binutils"],
    },
]
