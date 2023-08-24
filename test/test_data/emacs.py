# Copyright (C) 2023 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later

mapping_test_data = [
    {
        "product": "emacs",
        "version": "28.2",
        "version_strings": [r"$Id: GNU Emacs 28.2"],
    },
    {
        "product": "emacs",
        "version": "25.2",
        "version_strings": [r"$Id: GNU Emacs 25.2"],
    },
    {
        "product": "emacs",
        "version": "26.1",
        "version_strings": [r"$Id: GNU Emacs 26.1"],
    },
]
package_test_data = [
    {
        "url": "http://ports.ubuntu.com/pool/main/e/emacs25/",
        "package_name": "emacs25_25.2+1-6_arm64.deb",
        "product": "emacs",
        "version": "25.2",
    },
    {
        "url": "http://rpmfind.net/linux/centos/8-stream/AppStream/x86_64/os/Packages/",
        "package_name": "emacs-26.1-7.el8.x86_64.rpm",
        "product": "emacs",
        "version": "26.1",
    },
]
