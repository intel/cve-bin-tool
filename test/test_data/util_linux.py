# Copyright (C) 2022 Orange
# SPDX-License-Identifier: GPL-3.0-or-later

mapping_test_data = [
    {
        "product": "util-linux",
        "version": "2.38.1",
        "version_strings": ["util-linux 2.38.1"],
    },
    {
        "product": "util-linux",
        "version": "2.26.2",
        "version_strings": ["util-linux-2.26.2"],
    },
]
package_test_data = [
    {
        "url": "http://rpmfind.net/linux/fedora/linux/development/rawhide/Everything/aarch64/os/Packages/u/",
        "package_name": "util-linux-2.38.1-2.fc38.aarch64.rpm",
        "product": "util-linux",
        "version": "2.38.1",
    },
    {
        "url": "http://rpmfind.net/linux/fedora/linux/development/rawhide/Everything/x86_64/os/Packages/u/",
        "package_name": "util-linux-2.38.1-2.fc38.i686.rpm",
        "product": "util-linux",
        "version": "2.38.1",
    },
    {
        "url": "http://ftp.fr.debian.org/debian/pool/main/u/util-linux/",
        "package_name": "util-linux-extra_2.38.1-1.1+b1_amd64.deb",
        "product": "util-linux",
        "version": "2.38.1",
    },
    {
        "url": "http://ftp.fr.debian.org/debian/pool/main/u/util-linux/",
        "package_name": "util-linux-extra_2.38.1-1.1+b1_arm64.deb",
        "product": "util-linux",
        "version": "2.38.1",
    },
    {
        "url": "https://downloads.openwrt.org/releases/packages-19.07/x86_64/base/",
        "package_name": "blkid_2.34-1_x86_64.ipk",
        "product": "util-linux",
        "version": "2.34",
    },
    {
        "url": "https://downloads.openwrt.org/releases/22.03.0/packages/x86_64/base/",
        "package_name": "fdisk_2.37.4-1_x86_64.ipk",
        "product": "util-linux",
        "version": "2.37.4",
    },
]
