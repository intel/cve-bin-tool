# Copyright (C) 2021 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later

mapping_test_data = [
    {"product": "cronie", "version": "1.5.7", "version_strings": ["cronie 1.5.7"]},
    {"product": "cronie", "version": "1.5.5", "version_strings": ["cronie 1.5.5"]},
]
package_test_data = [
    {
        "url": "https://download-ib01.fedoraproject.org/pub/fedora/linux/releases/34/Everything/x86_64/os/Packages/c/",
        "package_name": "cronie-1.5.7-1.fc34.x86_64.rpm",
        "product": "cronie",
        "version": "1.5.7",
    },
    {
        "url": "https://download-ib01.fedoraproject.org/pub/fedora/linux/releases/33/Everything/x86_64/os/Packages/c/",
        "package_name": "cronie-1.5.5-4.fc33.x86_64.rpm",
        "product": "cronie",
        "version": "1.5.5",
    },
]
