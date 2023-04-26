# Copyright (C) 2021 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later

mapping_test_data = [
    {
        "product": "open-vm-tools",
        "version": "11.3.0",
        "version_strings": [
            r"/builddir/build/BUILD/open-vm-tools-11.3.0-18090558/lib/include/dynbuf.h"
        ],
    },
    {
        "product": "open-vm-tools",
        "version": "10.3.10",
        "version_strings": [
            r"/home/buildozer/aports/community/open-vm-tools/src/open-vm-tools-stable-10.3.10/open-vm-tools/lib/include/memaligned.h",
        ],
    },
]
package_test_data = [
    {
        "url": "https://download-ib01.fedoraproject.org/pub/fedora/linux/updates/33/Everything/aarch64/Packages/o/",
        "package_name": "open-vm-tools-11.3.0-1.fc33.aarch64.rpm",
        "product": "open-vm-tools",
        "version": "11.3.0",
    },
    {
        "url": "http://dl-cdn.alpinelinux.org/alpine/v3.11/community/x86_64/",
        "package_name": "open-vm-tools-10.3.10-r2.apk",
        "product": "open-vm-tools",
        "version": "10.3.10",
    },
    {
        "url": "http://ftp.br.debian.org/debian/pool/main/o/open-vm-tools/",
        "package_name": "open-vm-tools_10.1.5-5055683-4+deb9u2_amd64.deb",
        "product": "open-vm-tools",
        "version": "10.1.5",
    },
]
