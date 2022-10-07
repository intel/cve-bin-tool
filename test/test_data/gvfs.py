# Copyright (C) 2022 Orange
# SPDX-License-Identifier: GPL-3.0-or-later

mapping_test_data = [
    {"product": "gvfs", "version": "1.50.2", "version_strings": ["gvfs 1.50.2"]},
    {"product": "gvfs", "version": "1.22.2", "version_strings": ["gvfs/1.22.2"]},
]
package_test_data = [
    {
        "url": "http://rpmfind.net/linux/opensuse/ports/aarch64/tumbleweed/repo/oss/aarch64/",
        "package_name": "gvfs-1.50.2-2.2.aarch64.rpm",
        "product": "gvfs",
        "version": "1.50.2",
    },
    {
        "url": "http://rpmfind.net/linux/opensuse/ports/armv6hl/tumbleweed/repo/oss/armv6hl/",
        "package_name": "gvfs-1.50.2-2.2.armv6hl.rpm",
        "product": "gvfs",
        "version": "1.50.2",
    },
    {
        "url": "http://ftp.fr.debian.org/debian/pool/main/g/gvfs/",
        "package_name": "gvfs-backends_1.22.2-1_amd64.deb",
        "product": "gvfs",
        "version": "1.22.2",
    },
    {
        "url": "http://ftp.fr.debian.org/debian/pool/main/g/gvfs/",
        "package_name": "gvfs-backends_1.22.2-1_armel.deb",
        "product": "gvfs",
        "version": "1.22.2",
    },
]
