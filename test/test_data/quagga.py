# Copyright (C) 2022 Orange
# SPDX-License-Identifier: GPL-3.0-or-later

mapping_test_data = [
    {
        "product": "quagga",
        "version": "1.2.4",
        "version_strings": ["Quagga (version 1.2.4"],
    }
]
package_test_data = [
    {
        "url": "http://rpmfind.net/linux/fedora/linux/releases/35/Everything/aarch64/os/Packages/q/",
        "package_name": "quagga-1.2.4-19.fc35.aarch64.rpm",
        "product": "quagga",
        "version": "1.2.4",
    },
    {
        "url": "http://rpmfind.net/linux/fedora/linux/releases/35/Everything/armhfp/os/Packages/q/",
        "package_name": "quagga-1.2.4-19.fc35.armv7hl.rpm",
        "product": "quagga",
        "version": "1.2.4",
    },
    {
        "url": "http://ftp.fr.debian.org/debian/pool/main/q/quagga/",
        "package_name": "quagga-core_1.1.1-3+deb9u2_amd64.deb",
        "product": "quagga",
        "version": "1.1.1",
    },
    {
        "url": "http://ftp.fr.debian.org/debian/pool/main/q/quagga/",
        "package_name": "quagga-core_1.1.1-3+deb9u2_arm64.deb",
        "product": "quagga",
        "version": "1.1.1",
    },
    {
        "url": "https://downloads.openwrt.org/releases/packages-19.07/x86_64/routing/",
        "package_name": "quagga-libzebra_1.1.1-1_x86_64.ipk",
        "product": "quagga",
        "version": "1.1.1",
    },
]
