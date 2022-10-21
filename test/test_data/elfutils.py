# Copyright (C) 2022 Orange
# SPDX-License-Identifier: GPL-3.0-or-later

mapping_test_data = [
    {"product": "elfutils", "version": "0.187", "version_strings": ["elfutils\n0.187"]},
    {"product": "elfutils", "version": "0.159", "version_strings": ["0.159\nelfutils"]},
]
package_test_data = [
    {
        "url": "http://rpmfind.net/linux/opensuse/ports/riscv/tumbleweed/repo/oss/riscv64/",
        "package_name": "elfutils-0.187-9.2.riscv64.rpm",
        "product": "elfutils",
        "version": "0.187",
    },
    {
        "url": "http://rpmfind.net/linux/fedora/linux/development/rawhide/Everything/aarch64/os/Packages/e/",
        "package_name": "elfutils-0.187-8.fc38.aarch64.rpm",
        "product": "elfutils",
        "version": "0.187",
    },
    {
        "url": "http://ftp.fr.debian.org/debian/pool/main/e/elfutils/",
        "package_name": "elfutils_0.159-4.2_amd64.deb",
        "product": "elfutils",
        "version": "0.159",
    },
    {
        "url": "http://ftp.fr.debian.org/debian/pool/main/e/elfutils/",
        "package_name": "elfutils_0.159-4.2_armel.deb",
        "product": "elfutils",
        "version": "0.159",
    },
]
