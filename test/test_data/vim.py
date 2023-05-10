# Copyright (C) 2023 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later

mapping_test_data = [
    {
        "product": "vim",
        "version": "9.0.1429",
        "version_strings": ["vim-9.0.1429"],
    },
    {
        "product": "vim",
        "version": "8.2.2434",
        "version_strings": ["vim-8.2.2434"],
    },
    {
        "product": "vim",
        "version": "8.1.2269",
        "version_strings": [
            "vim-8.1.2269",
            "E136: viminfo: Too many errors, skipping rest of file",
        ],
    },
]
package_test_data = [
    {
        "url": "https://dl.fedoraproject.org/pub/fedora/linux/releases/38/Everything/aarch64/os/Packages/v/",
        "package_name": "vim-enhanced-9.0.1429-1.fc38.aarch64.rpm",
        "product": "vim",
        "version": "9.0.1429",
    },
    {
        "url": "http://ftp.de.debian.org/debian/pool/main/v/vim/",
        "package_name": "vim_8.2.2434-3+deb11u1_amd64.deb",
        "product": "vim",
        "version": "8.2.2434",
    },
    {
        "url": "http://archive.ubuntu.com/ubuntu/pool/main/v/vim/",
        "package_name": "vim_8.1.2269-1ubuntu5_amd64.deb",
        "product": "vim",
        "version": "8.1.2269",
    },
]
