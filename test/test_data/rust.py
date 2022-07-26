# Copyright (C) 2022 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later

mapping_test_data = [
    {
        "product": "rust",
        "version": "1.58.0",
        "version_strings": ["rustc-1.58.0"],
    },
    {
        "product": "rust",
        "version": "1.52.0",
        "version_strings": ["rustc-1.52.0"],
    },
]
package_test_data = [
    {
        "url": "https://rpmfind.net/linux/fedora/linux/releases/35/Everything/x86_64/os/Packages/r/",
        "package_name": "rust-1.55.0-1.fc35.x86_64.rpm",
        "product": "rust",
        "version": "1.55.0",
    },
    {
        "url": "http://ftp.us.debian.org/debian/pool/main/r/rustc/",
        "package_name": "rustc_1.48.0+dfsg1-2_amd64.deb",
        "product": "rust",
        "version": "1.48.0",
    },
]
