# Copyright (C) 2021 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later

mapping_test_data = [
    {
        "product": "pcsc-lite",
        "version": "1.9.1",
        "version_strings": [
            "%s:%d:%s() pcsc-lite 1.9.1 daemon ready.",
        ],
    },
    {
        "product": "pcsc-lite",
        "version": "1.8.25",
        "version_strings": [
            "%s:%d:%s() pcsc-lite 1.8.25 daemon ready.",
        ],
    },
]
package_test_data = [
    {
        "url": "https://download-ib01.fedoraproject.org/pub/fedora/linux/updates/33/Everything/x86_64/Packages/p/",
        "package_name": "pcsc-lite-1.9.1-1.fc33.x86_64.rpm",
        "product": "pcsc-lite",
        "version": "1.9.1",
    },
    {
        "url": "http://dl-cdn.alpinelinux.org/alpine/v3.11/main/x86_64/",
        "package_name": "pcsc-lite-1.8.25-r2.apk",
        "product": "pcsc-lite",
        "version": "1.8.25",
    },
]
