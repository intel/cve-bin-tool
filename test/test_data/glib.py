# Copyright (C) 2022 Orange
# SPDX-License-Identifier: GPL-3.0-or-later

mapping_test_data = [
    {"product": "glib", "version": "2.74.0", "version_strings": ["GDBus 2.74.0"]},
    {"product": "glib", "version": "2.74.0", "version_strings": ["glib-2.74.0"]},
]
package_test_data = [
    {
        "url": "http://rpmfind.net/linux/fedora/linux/development/rawhide/Everything/aarch64/os/Packages/g/",
        "package_name": "glib2-2.74.0-3.fc38.aarch64.rpm",
        "product": "glib",
        "version": "2.74.0",
    },
    {
        "url": "http://rpmfind.net/linux/fedora/linux/development/rawhide/Everything/x86_64/os/Packages/g/",
        "package_name": "glib2-2.74.0-3.fc38.i686.rpm",
        "product": "glib",
        "version": "2.74.0",
    },
    {
        "url": "http://ftp.fr.debian.org/debian/pool/main/g/glib2.0/",
        "package_name": "libglib2.0-0_2.50.3-2+deb9u2_arm64.deb",
        "product": "glib",
        "version": "2.50.3",
    },
    {
        "url": "https://downloads.openwrt.org/releases/packages-19.07/x86_64/packages/",
        "package_name": "glib2_2.58.3-5_x86_64.ipk",
        "product": "glib",
        "version": "2.58.3",
    },
]
