# Copyright (C) 2021 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later

mapping_test_data = [
    {
        "product": "kbd",
        "version": "2.4.0",
        "version_strings": [
            "KDGKBDIACR(UC): %s: Unable to get accent table",
            "kbd 2.4.0",
        ],
    },
    {
        "product": "kbd",
        "version": "2.0.4",
        "version_strings": [
            "KDGKBDIACR(UC): %s: Unable to get accent table",
            "kbd 2.0.4",
        ],
    },
]
package_test_data = [
    {
        "url": "https://download-ib01.fedoraproject.org/pub/fedora/linux/releases/34/Everything/x86_64/os/Packages/k/",
        "package_name": "kbd-2.4.0-2.fc34.x86_64.rpm",
        "product": "kbd",
        "version": "2.4.0",
    },
    {
        "url": "http://ports.ubuntu.com/pool/main/k/kbd/",
        "package_name": "kbd_2.0.4-2ubuntu1_arm64.deb",
        "product": "kbd",
        "version": "2.0.4",
    },
]
