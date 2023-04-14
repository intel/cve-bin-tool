# Copyright (C) 2021 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later

mapping_test_data = [
    {
        "product": "sane-backends",
        "version": "1.0.31",
        "version_strings": ["sane-backends 1.0.31"],
    },
    {
        "product": "sane-backends",
        "version": "1.0.27",
        "version_strings": ["sane-backends 1.0.27"],
    },
]
package_test_data = [
    {
        "url": "https://download-ib01.fedoraproject.org/pub/fedora/linux/releases/33/Everything/aarch64/os/Packages/s/",
        "package_name": "sane-backends-1.0.31-2.fc33.aarch64.rpm",
        "product": "sane-backends",
        "version": "1.0.31",
    },
    {
        "url": "https://repo.almalinux.org/almalinux/8/AppStream/x86_64/os/Packages/",
        "package_name": "sane-backends-1.0.27-22.el8.x86_64.rpm",
        "product": "sane-backends",
        "version": "1.0.27",
    },
]
