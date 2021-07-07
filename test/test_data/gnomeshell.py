# Copyright (C) 2021 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later

mapping_test_data = [
    {
        "product": "gnome-shell",
        "version": "3.38.4",
        "version_strings": [
            "var PACKAGE_NAME = 'gnome-shell';\n/* The version of this package */\nvar PACKAGE_VERSION = '3.38.4';",
            "* Creates a window using gnome-shell-perf-helper for testing purposes.",
        ],
    },
    {
        "product": "gnome-shell",
        "version": "40.2",
        "version_strings": [
            "var PACKAGE_NAME = 'gnome-shell';\n/* The version of this package */\nvar PACKAGE_VERSION = '40.2';",
            "* Creates a window using gnome-shell-perf-helper for testing purposes.",
        ],
    },
]
package_test_data = [
    {
        "url": "http://archive.ubuntu.com/ubuntu/pool/main/g/gnome-shell/",
        "package_name": "gnome-shell_3.38.4-1ubuntu2_amd64.deb",
        "product": "gnome-shell",
        "version": "3.38.4",
    },
    {
        "url": "https://download-ib01.fedoraproject.org/pub/fedora/linux/development/rawhide/Everything/x86_64/os/Packages/g/",
        "package_name": "gnome-shell-40.2-1.fc35.x86_64.rpm",
        "product": "gnome-shell",
        "version": "40.2",
    },
]
