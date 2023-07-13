# Copyright (C) 2022 Orange
# SPDX-License-Identifier: GPL-3.0-or-later

mapping_test_data = [
    {"product": "tor", "version": "0.4.7.10", "version_strings": ["on Tor 0.4.7.10"]}
]
package_test_data = [
    {
        "url": "http://rpmfind.net/linux/opensuse/ports/riscv/tumbleweed/repo/oss/riscv64/",
        "package_name": "tor-0.4.7.10-4.1.riscv64.rpm",
        "product": "tor",
        "version": "0.4.7.10",
    },
    {
        "url": "http://rpmfind.net/linux/mageia/distrib/cauldron/aarch64/media/core/release/",
        "package_name": "tor-0.4.7.10-2.mga9.aarch64.rpm",
        "product": "tor",
        "version": "0.4.7.10",
    },
    {
        "url": "http://ftp.fr.debian.org/debian/pool/main/t/tor/",
        "package_name": "tor_0.2.9.16-1_arm64.deb",
        "product": "tor",
        "version": "0.2.9.16",
    },
    {
        "url": "https://downloads.openwrt.org/releases/packages-19.07/x86_64/packages/",
        "package_name": "tor_0.4.5.10-1_x86_64.ipk",
        "product": "tor",
        "version": "0.4.5.10",
    },
]
