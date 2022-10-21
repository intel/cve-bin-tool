# Copyright (C) 2022 Orange
# SPDX-License-Identifier: GPL-3.0-or-later

mapping_test_data = [
    {"product": "libgit2", "version": "1.5.0", "version_strings": ["libgit2 1.5.0"]}
]
package_test_data = [
    {
        "url": "http://rpmfind.net/linux/opensuse/ports/aarch64/tumbleweed/repo/oss/aarch64/",
        "package_name": "libgit2-1.5.0-1.3.aarch64.rpm",
        "product": "libgit2",
        "version": "1.5.0",
    },
    {
        "url": "http://rpmfind.net/linux/opensuse/ports/armv6hl/tumbleweed/repo/oss/armv6hl/",
        "package_name": "libgit2-1.5.0-1.3.armv6hl.rpm",
        "product": "libgit2",
        "version": "1.5.0",
    },
    {
        "url": "http://ftp.fr.debian.org/debian/pool/main/libg/libgit2/",
        "package_name": "libgit2-1.1_1.1.0+dfsg.1-4.1+b1_amd64.deb",
        "product": "libgit2",
        "version": "1.1.0",
    },
    {
        "url": "http://ftp.fr.debian.org/debian/pool/main/libg/libgit2/",
        "package_name": "libgit2-1.1_1.1.0+dfsg.1-4.1+b1_arm64.deb",
        "product": "libgit2",
        "version": "1.1.0",
    },
]
