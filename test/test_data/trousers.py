# Copyright (C) 2021 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later

mapping_test_data = [
    {
        "product": "trousers",
        "version": "0.3.15",
        "version_strings": [
            "TrouSerS Config file %s not found, using defaults.",
            "TrouSerS Could not retrieve client address info",
            "TrouSerS Could not set IPv6 socket option properly.",
            "trousers 0.3.15",
        ],
    },
    {
        "product": "trousers",
        "version": "0.3.13",
        "version_strings": [
            "TrouSerS Config file %s not found, using defaults.",
            "TrouSerS Could not retrieve client address info",
            "TrouSerS Could not set IPv6 socket option properly.",
            "trousers 0.3.13",
        ],
    },
]
package_test_data = [
    {
        "url": "https://download-ib01.fedoraproject.org/pub/fedora/linux/releases/34/Everything/x86_64/os/Packages/t/",
        "package_name": "trousers-0.3.15-2.fc34.x86_64.rpm",
        "product": "trousers",
        "version": "0.3.15",
    },
    {
        "url": "http://ftp.br.debian.org/debian/pool/main/t/trousers/",
        "package_name": "trousers_0.3.13-3_amd64.deb",
        "product": "trousers",
        "version": "0.3.13",
    },
]
