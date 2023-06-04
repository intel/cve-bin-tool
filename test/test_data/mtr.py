# Copyright (C) 2021 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later

mapping_test_data = [
    {
        "product": "mtr",
        "version": "0.94",
        "version_strings": [
            "mtr 0.94",
            "Mtr_Version,Start_Time,Status,Host,Hop,Ip,",
            "protocol unsupported by mtr-packet interface",
        ],
    },
    {
        "product": "mtr",
        "version": "0.87",
        "version_strings": [
            "mtr 0.87",
            "Mtr_Version,Start_Time,Status,Host,Hop,Ip,",
        ],
    },
]
package_test_data = [
    {
        "url": "https://download-ib01.fedoraproject.org/pub/fedora/linux/releases/34/Everything/x86_64/os/Packages/m/",
        "package_name": "mtr-0.94-2.fc34.x86_64.rpm",
        "product": "mtr",
        "version": "0.94",
    },
    {
        "url": "http://ftp.br.debian.org/debian/pool/main/m/mtr/",
        "package_name": "mtr_0.87-1_arm64.deb",
        "product": "mtr",
        "version": "0.87",
    },
]
