# Copyright (C) 2021 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later

mapping_test_data = [
    {
        "product": "node.js",
        "version": "9.3.0",
        "version_strings": ["https://nodejs.org/download/release/v", "/node v9.3.0 "],
    }
]
package_test_data = [
    {
        "url": "http://mirror.centos.org/centos/7/sclo/x86_64/rh/Packages/r/",
        "package_name": "rh-nodejs14-nodejs-14.16.0-1.el7.x86_64.rpm",
        "product": "node.js",
        "version": "14.16.0",
        "other_products": ["libuv", "zlib"],
    },
    {
        "url": "http://ftp.fr.debian.org/debian/pool/main/n/nodejs/",
        "package_name": "nodejs_0.10.29~dfsg-2_amd64.deb",
        "product": "node.js",
        "version": "0.10.29",
    },
    {
        "url": "https://downloads.openwrt.org/releases/packages-19.07/x86_64/packages/",
        "package_name": "node_v8.16.1-1_x86_64.ipk",
        "product": "node.js",
        "version": "8.16.1",
    },
]
