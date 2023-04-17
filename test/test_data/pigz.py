# Copyright (C) 2021 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later

mapping_test_data = [
    {
        "product": "pigz",
        "version": "2.6",
        "version_strings": [
            "-L, --license        Display the pigz license and quit",
            "-V  --version        Show the version of pigz",
            "cannot provide files in PIGZ environment variable",
            "specified, stdin will be compressed to stdout. pigz does what gzip does,",
            "pigz 2.6",
        ],
    },
    {
        "product": "pigz",
        "version": "2.4",
        "version_strings": [
            "pigz 2.4",
            "-L, --license        Display the pigz license and quit",
            "-V  --version        Show the version of pigz",
            "cannot provide files in PIGZ environment variable",
            "specified, stdin will be compressed to stdout. pigz does what gzip does,",
        ],
    },
]
package_test_data = [
    {
        "url": "http://dl-cdn.alpinelinux.org/alpine/v3.14/main/x86_64/",
        "package_name": "pigz-2.6-r0.apk",
        "product": "pigz",
        "version": "2.6",
    },
    {
        "url": "https://download-ib01.fedoraproject.org/pub/fedora/linux/releases/33/Everything/x86_64/os/Packages/p/",
        "package_name": "pigz-2.4-7.fc33.x86_64.rpm",
        "product": "pigz",
        "version": "2.4",
    },
    {
        "url": "http://ftp.fr.debian.org/debian/pool/main/p/pigz/",
        "package_name": "pigz_2.3.1-2_amd64.deb",
        "product": "pigz",
        "version": "2.3.1",
    },
    {
        "url": "https://downloads.openwrt.org/releases/22.03.3/packages/x86_64/packages/",
        "package_name": "pigz_2.4-1_x86_64.ipk",
        "product": "pigz",
        "version": "2.4",
    },
]
