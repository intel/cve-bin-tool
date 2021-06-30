# Copyright (C) 2021 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later

mapping_test_data = [
    {
        "product": "bolt",
        "version": "0.9",
        "version_strings": ["bolt 0.9", "bolt 0.9 starting up."],
    },
    {
        "product": "bolt",
        "version": "0.9.1",
        "version_strings": ["bolt 0.9.1", "bolt 0.9.1 starting up."],
    },
]
package_test_data = [
    {
        "url": "http://archive.ubuntu.com/ubuntu/pool/main/b/bolt/",
        "package_name": "bolt_0.9.1-1_amd64.deb",
        "product": "bolt",
        "version": "0.9.1",
    },
    {
        "url": "https://download-ib01.fedoraproject.org/pub/fedora/linux/releases/33/Everything/aarch64/os/Packages/b/",
        "package_name": "bolt-0.9-3.fc33.aarch64.rpm",
        "product": "bolt",
        "version": "0.9",
    },
]
