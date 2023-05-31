# Copyright (C) 2022 Orange
# SPDX-License-Identifier: GPL-3.0-or-later

mapping_test_data = [
    {"product": "bluez", "version": "5.28", "version_strings": ["bluez-5.28"]},
    {
        "product": "bluez",
        "version": "5.50",
        "version_strings": ["5.50\nUsage: hcidump"],
    },
    {"product": "bluez", "version": "5.50", "version_strings": ["5.50\nhcitool"]},
    {"product": "bluez", "version": "5.66", "version_strings": ["5.66\nBlueZ"]},
]
package_test_data = [
    {
        "url": "http://rpmfind.net/linux/fedora/linux/development/rawhide/Everything/aarch64/os/Packages/b/",
        "package_name": "bluez-5.66-5.fc38.aarch64.rpm",
        "product": "bluez",
        "version": "5.66",
    },
    {
        "url": "http://ftp.fr.debian.org/debian/pool/main/b/bluez/",
        "package_name": "bluez_5.50-1.2~deb10u2_amd64.deb",
        "product": "bluez",
        "version": "5.50",
    },
    {
        "url": "https://downloads.openwrt.org/releases/packages-19.07/x86_64/packages/",
        "package_name": "bluez-daemon_5.50-5_x86_64.ipk",
        "product": "bluez",
        "version": "5.50",
    },
]
