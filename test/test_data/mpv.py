# Copyright (C) 2022 Orange
# SPDX-License-Identifier: GPL-3.0-or-later

mapping_test_data = [
    {"product": "mpv", "version": "0.34.1", "version_strings": ["mpv 0.34.1"]}
]
package_test_data = [
    {
        "url": "http://rpmfind.net/linux/fedora/linux/development/rawhide/Everything/aarch64/os/Packages/m/",
        "package_name": "mpv-0.34.1-11.fc38.aarch64.rpm",
        "product": "mpv",
        "version": "0.34.1",
    },
    {
        "url": "http://rpmfind.net/linux/fedora-secondary/development/rawhide/Everything/ppc64le/os/Packages/m/",
        "package_name": "mpv-0.34.1-11.fc38.ppc64le.rpm",
        "product": "mpv",
        "version": "0.34.1",
    },
    {
        "url": "http://ftp.fr.debian.org/debian/pool/main/m/mpv/",
        "package_name": "libmpv1_0.23.0-2+deb9u2_amd64.deb",
        "product": "mpv",
        "version": "0.23.0",
    },
    {
        "url": "http://ftp.fr.debian.org/debian/pool/main/m/mpv/",
        "package_name": "libmpv1_0.23.0-2+deb9u2_arm64.deb",
        "product": "mpv",
        "version": "0.23.0",
    },
]
