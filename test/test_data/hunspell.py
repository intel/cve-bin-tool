# Copyright (C) 2021 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later

mapping_test_data = [
    {
        "product": "hunspell",
        "version": "1.7.0",
        "version_strings": [
            "Example: hunspell -d en_US file.txt    # interactive spelling",
            "@(#) International Ispell Version 3.2.06 (but really Hunspell 1.7.0)",
        ],
    },
    {
        "product": "hunspell",
        "version": "1.6.2",
        "version_strings": [
            "Example: hunspell -d en_US file.txt    # interactive spelling",
            "@(#) International Ispell Version 3.2.06 (but really Hunspell 1.6.2)",
        ],
    },
]
package_test_data = [
    {
        "url": "https://download-ib01.fedoraproject.org/pub/fedora/linux/releases/34/Everything/aarch64/os/Packages/h/",
        "package_name": "hunspell-1.7.0-9.fc34.aarch64.rpm",
        "product": "hunspell",
        "version": "1.7.0",
    },
    {
        "url": "http://ports.ubuntu.com/pool/universe/h/hunspell/",
        "package_name": "hunspell_1.6.2-1_arm64.deb",
        "product": "hunspell",
        "version": "1.6.2",
    },
]
