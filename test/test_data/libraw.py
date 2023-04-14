# Copyright (C) 2023 Orange
# SPDX-License-Identifier: GPL-3.0-or-later

mapping_test_data = [
    {
        "product": "libraw",
        "version": "0.20.2",
        "version_strings": [
            "0.20.2-Release\nOpening file\nStarting\nReading metadata\nAdjusting size\nReading RAW data"
        ],
    },
    {
        "product": "libraw",
        "version": "0.16.0",
        "version_strings": [
            "Out of order call of libraw function\nNo thumbnail in file\n0.16.0-Release"
        ],
    },
]
package_test_data = [
    {
        "url": "http://rpmfind.net/linux/fedora/linux/development/rawhide/Everything/aarch64/os/Packages/l/",
        "package_name": "LibRaw-0.20.2-7.fc37.aarch64.rpm",
        "product": "libraw",
        "version": "0.20.2",
    },
    {
        "url": "http://rpmfind.net/linux/fedora/linux/development/rawhide/Everything/x86_64/os/Packages/l/",
        "package_name": "LibRaw-0.20.2-7.fc37.i686.rpm",
        "product": "libraw",
        "version": "0.20.2",
    },
    {
        "url": "http://ftp.fr.debian.org/debian/pool/main/libr/libraw/",
        "package_name": "libraw10_0.16.0-9+deb8u3_armel.deb",
        "product": "libraw",
        "version": "0.16.0",
    },
    {
        "url": "http://ftp.fr.debian.org/debian/pool/main/libr/libraw/",
        "package_name": "libraw20_0.20.2-2+b1_arm64.deb",
        "product": "libraw",
        "version": "0.20.2",
    },
]
