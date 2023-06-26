# Copyright (C) 2022 Orange
# SPDX-License-Identifier: GPL-3.0-or-later

mapping_test_data = [
    {
        "product": "tcpreplay",
        "version": "4.4.3",
        "version_strings": ["4.4.3\ntcpreplay version"],
    }
]
package_test_data = [
    {
        "url": "http://rpmfind.net/linux/fedora/linux/development/rawhide/Everything/aarch64/os/Packages/t/",
        "package_name": "tcpreplay-4.4.3-2.fc38.aarch64.rpm",
        "product": "tcpreplay",
        "version": "4.4.3",
    },
    {
        "url": "http://ftp.fr.debian.org/debian/pool/main/t/tcpreplay/",
        "package_name": "tcpreplay_3.4.4-3_amd64.deb",
        "product": "tcpreplay",
        "version": "3.4.4",
    },
    {
        "url": "https://downloads.openwrt.org/releases/packages-19.07/x86_64/packages/",
        "package_name": "tcpreplay_4.3.4-1_x86_64.ipk",
        "product": "tcpreplay",
        "version": "4.3.4",
    },
]
