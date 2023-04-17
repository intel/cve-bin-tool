# Copyright (C) 2023 Orange
# SPDX-License-Identifier: GPL-3.0-or-later

mapping_test_data = [
    {
        "product": "libidn2",
        "version": "2.3.3",
        "version_strings": ["libidn2.so.0.3.8-2.3.3"],
    },
    {
        "product": "libidn2",
        "version": "2.3.0",
        "version_strings": ["Simon Josefsson, Tim Ruehsen\n2.3.0"],
    },
    {
        "product": "libidn2",
        "version": "2.0.5",
        "version_strings": ["2.0.5\nCopyright (C) 2011-2016  Simon Josefsson"],
    },
]
package_test_data = [
    {
        "url": "http://rpmfind.net/linux/fedora/linux/development/rawhide/Everything/aarch64/os/Packages/l/",
        "package_name": "libidn2-2.3.3-2.fc37.aarch64.rpm",
        "product": "libidn2",
        "version": "2.3.3",
    },
    {
        "url": "http://rpmfind.net/linux/fedora/linux/development/rawhide/Everything/x86_64/os/Packages/l/",
        "package_name": "libidn2-2.3.3-2.fc37.i686.rpm",
        "product": "libidn2",
        "version": "2.3.3",
    },
    {
        "url": "http://ftp.fr.debian.org/debian/pool/main/libi/libidn2/",
        "package_name": "libidn2-0_2.0.5-1+deb10u1_amd64.deb",
        "product": "libidn2",
        "version": "2.0.5",
    },
    {
        "url": "http://ftp.fr.debian.org/debian/pool/main/libi/libidn2/",
        "package_name": "libidn2-0_2.3.0-5_mips64el.deb",
        "product": "libidn2",
        "version": "2.3.0",
    },
    {
        "url": "https://downloads.openwrt.org/releases/packages-19.07/x86_64/packages/",
        "package_name": "libidn2_2.0.5-1_x86_64.ipk",
        "product": "libidn2",
        "version": "2.0.5",
    },
]
