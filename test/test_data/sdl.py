# Copyright (C) 2023 Orange
# SPDX-License-Identifier: GPL-3.0-or-later

mapping_test_data = [
    {
        "product": "simple_directmedia_layer",
        "version": "2.0.2",
        "version_strings": ["libsdl2-2.0.2"],
    },
    {
        "product": "simple_directmedia_layer",
        "version": "2.26.2",
        "version_strings": ["SDL2-2.26.2"],
    },
]
package_test_data = [
    {
        "url": "http://rpmfind.net/linux/fedora/linux/development/rawhide/Everything/aarch64/os/Packages/s/",
        "package_name": "SDL2-2.26.2-1.fc38.aarch64.rpm",
        "product": "simple_directmedia_layer",
        "version": "2.26.2",
    },
    {
        "url": "http://ftp.fr.debian.org/debian/pool/main/libs/libsdl2/",
        "package_name": "libsdl2-2.0-0_2.0.2+dfsg1-6_amd64.deb",
        "product": "simple_directmedia_layer",
        "version": "2.0.2",
    },
]
