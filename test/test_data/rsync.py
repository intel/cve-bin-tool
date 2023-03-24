# Copyright (C) 2022 Orange
# SPDX-License-Identifier: GPL-3.0-or-later

mapping_test_data = [
    {"product": "rsync", "version": "3.2.6", "version_strings": ["3.2.6\nrsync"]}
]

package_test_data = [
    {
        "url": "http://rpmfind.net/linux/fedora/linux/development/rawhide/Everything/aarch64/os/Packages/r/",
        "package_name": "rsync-3.2.6-2.fc38.aarch64.rpm",
        "product": "rsync",
        "version": "3.2.6",
    },
    {
        "url": "http://rpmfind.net/linux/fedora-secondary/development/rawhide/Everything/ppc64le/os/Packages/r/",
        "package_name": "rsync-3.2.6-2.fc38.ppc64le.rpm",
        "product": "rsync",
        "version": "3.2.6",
    },
    {
        "url": "http://ftp.fr.debian.org/debian/pool/main/r/rsync/",
        "package_name": "rsync_3.1.1-3+deb8u1_armel.deb",
        "product": "rsync",
        "version": "3.1.1",
        "other_products": ["zlib"],
    },
    {
        "url": "https://downloads.openwrt.org/releases/packages-19.07/x86_64/packages/",
        "package_name": "rsync_3.1.3-2_x86_64.ipk",
        "product": "rsync",
        "version": "3.1.3",
    },
]
