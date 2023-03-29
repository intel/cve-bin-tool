# Copyright (C) 2022 Orange
# SPDX-License-Identifier: GPL-3.0-or-later

mapping_test_data = [
    {
        "product": "network_block_device",
        "version": "3.24",
        "version_strings": ["nbd-server version 3.24"],
    },
    {
        "product": "network_block_device",
        "version": "3.15.2",
        "version_strings": ["nbd-server version 3.15.2"],
    },
]
package_test_data = [
    {
        "url": "http://rpmfind.net/linux/opensuse/distribution/leap/15.4/repo/oss/aarch64/",
        "package_name": "nbd-3.24-150000.3.3.1.aarch64.rpm",
        "product": "network_block_device",
        "version": "3.24",
    },
    {
        "url": "http://rpmfind.net/linux/opensuse/distribution/leap/15.4/repo/oss/ppc64le/",
        "package_name": "nbd-3.24-150000.3.3.1.ppc64le.rpm",
        "product": "network_block_device",
        "version": "3.24",
    },
    {
        "url": "http://ftp.fr.debian.org/debian/pool/main/n/nbd/",
        "package_name": "nbd-server_3.15.2-3_amd64.deb",
        "product": "network_block_device",
        "version": "3.15.2",
    },
    {
        "url": "http://ftp.fr.debian.org/debian/pool/main/n/nbd/",
        "package_name": "nbd-client_3.15.2-3_arm64.deb",
        "product": "network_block_device",
        "version": "3.15.2",
    },
    {
        "url": "https://downloads.openwrt.org/releases/packages-19.07/x86_64/packages/",
        "package_name": "nbd_3.19-2_x86_64.ipk",
        "product": "network_block_device",
        "version": "3.19",
    },
]
