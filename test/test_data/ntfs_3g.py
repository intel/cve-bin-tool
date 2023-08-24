# Copyright (C) 2023 Orange
# SPDX-License-Identifier: GPL-3.0-or-later

mapping_test_data = [
    {
        "product": "ntfs-3g",
        "version": "2017.3.23",
        "version_strings": ["ntfs-3g\n2017.3.23"],
    },
    {
        "product": "ntfs-3g",
        "version": "2022.10.3",
        "version_strings": ["2022.10.3\nntfs-3g"],
    },
]
package_test_data = [
    {
        "url": "http://rpmfind.net/linux/fedora/linux/development/rawhide/Everything/aarch64/os/Packages/n/",
        "package_name": "ntfs-3g-2022.10.3-2.fc38.aarch64.rpm",
        "product": "ntfs-3g",
        "version": "2022.10.3",
    },
    {
        "url": "http://ftp.fr.debian.org/debian/pool/main/n/ntfs-3g/",
        "package_name": "ntfs-3g_2017.3.23AR.3-3+deb10u2_amd64.deb",
        "product": "ntfs-3g",
        "version": "2017.3.23",
    },
    {
        "url": "https://downloads.openwrt.org/releases/packages-19.07/x86_64/packages/",
        "package_name": "ntfs-3g_2017.3.23-3-fuseint_x86_64.ipk",
        "product": "ntfs-3g",
        "version": "2017.3.23",
    },
]
