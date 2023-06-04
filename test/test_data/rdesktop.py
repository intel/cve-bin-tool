# Copyright (C) 2022 Orange
# SPDX-License-Identifier: GPL-3.0-or-later

mapping_test_data = [
    {
        "product": "rdesktop",
        "version": "1.9.0",
        "version_strings": [
            "rdesktop: A Remote Desktop Protocol client.\nVersion 1.9.0"
        ],
    }
]
package_test_data = [
    {
        "url": "http://rpmfind.net/linux/fedora/linux/development/rawhide/Everything/aarch64/os/Packages/r/",
        "package_name": "rdesktop-1.9.0-9.fc37.aarch64.rpm",
        "product": "rdesktop",
        "version": "1.9.0",
    },
    {
        "url": "http://rpmfind.net/linux/fedora-secondary/development/rawhide/Everything/ppc64le/os/Packages/r/",
        "package_name": "rdesktop-1.9.0-9.fc37.ppc64le.rpm",
        "product": "rdesktop",
        "version": "1.9.0",
    },
    {
        "url": "http://ftp.fr.debian.org/debian/pool/main/r/rdesktop/",
        "package_name": "rdesktop_1.8.2-3+deb8u1_amd64.deb",
        "product": "rdesktop",
        "version": "1.8.2",
    },
    {
        "url": "http://ftp.fr.debian.org/debian/pool/main/r/rdesktop/",
        "package_name": "rdesktop_1.8.2-3+deb8u1_armel.deb",
        "product": "rdesktop",
        "version": "1.8.2",
    },
]
