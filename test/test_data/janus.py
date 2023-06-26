# Copyright (C) 2022 Orange
# SPDX-License-Identifier: GPL-3.0-or-later

mapping_test_data = [
    {
        "product": "janus",
        "version": "1.1.0",
        "version_strings": ["not-a-git-repo\n1.1.0\njanus"],
    },
    {"product": "janus", "version": "0.9.2", "version_strings": ["janus_mkdir\n0.9.2"]},
]
package_test_data = [
    {
        "url": "http://rpmfind.net/linux/opensuse/ports/aarch64/tumbleweed/repo/oss/aarch64/",
        "package_name": "janus-gateway-1.1.0-1.1.aarch64.rpm",
        "product": "janus",
        "version": "1.1.0",
    },
    {
        "url": "http://rpmfind.net/linux/opensuse/ports/armv6hl/tumbleweed/repo/oss/armv6hl/",
        "package_name": "janus-gateway-1.1.0-1.1.armv6hl.rpm",
        "product": "janus",
        "version": "1.1.0",
    },
    {
        "url": "http://ftp.fr.debian.org/debian/pool/main/j/janus/",
        "package_name": "janus_0.9.2-1~bpo10+1_amd64.deb",
        "product": "janus",
        "version": "0.9.2",
    },
]
