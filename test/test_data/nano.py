# Copyright (C) 2021 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later

mapping_test_data = [
    {
        "product": "nano",
        "version": "5.4",
        "version_strings": [
            r"Usage: nano [OPTIONS] [[+LINE[,COLUMN]] FILE]...",
            r"Welcome to nano.  For basic help, type Ctrl+G.",
            r"When a filename is '-', nano reads data from standard input.",
            r"If needed, use nano with the -I option to adjust your nanorc settings.",
            r"Nano will be unable to load or save search history or cursor positions.",
            r"GNU nano 5.4",
        ],
    },
    {
        "product": "nano",
        "version": "4.6",
        "version_strings": [
            r"Usage: nano [OPTIONS] [[+LINE[,COLUMN]] FILE]...",
            r"When a filename is '-', nano reads data from standard input.",
            r"If needed, use nano with the -I option to adjust your nanorc settings.",
            r"Nano will be unable to load or save search history or cursor positions.",
            r"GNU nano 4.6",
        ],
    },
]
package_test_data = [
    {
        "url": "http://ports.ubuntu.com/pool/main/n/nano/",
        "package_name": "nano_5.4-2build1_arm64.deb",
        "product": "nano",
        "version": "5.4",
    },
    {
        "url": "https://dl-cdn.alpinelinux.org/alpine/v3.11/main/x86_64/",
        "package_name": "nano-4.6-r0.apk",
        "product": "nano",
        "version": "4.6",
    },
    {
        "url": "http://ftp.fr.debian.org/debian/pool/main/n/nano/",
        "package_name": "nano_2.2.6-3_amd64.deb",
        "product": "nano",
        "version": "2.2.6",
    },
    {
        "url": "https://downloads.openwrt.org/releases/packages-19.07/x86_64/packages/",
        "package_name": "nano_6.2-1_x86_64.ipk",
        "product": "nano",
        "version": "6.2",
    },
]
