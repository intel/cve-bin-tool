# Copyright (C) 2022 Orange
# SPDX-License-Identifier: GPL-3.0-or-later

mapping_test_data = [
    {
        "product": "libssh",
        "version": "0.7.6",
        "version_strings": ["SSH-2.0-libssh_0.7.6"],
    },
    {
        "product": "libssh",
        "version": "0.10.4",
        "version_strings": ["SSH-2.0-libssh_0.10.4"],
    },
]
package_test_data = [
    {
        "url": "http://rpmfind.net/linux/fedora/linux/development/rawhide/Everything/aarch64/os/Packages/l/",
        "package_name": "libssh-0.10.4-1.fc38.aarch64.rpm",
        "product": "libssh",
        "version": "0.10.4",
    },
    {
        "url": "http://rpmfind.net/linux/fedora/linux/development/rawhide/Everything/x86_64/os/Packages/l/",
        "package_name": "libssh-0.10.4-1.fc38.i686.rpm",
        "product": "libssh",
        "version": "0.10.4",
    },
    {
        "url": "http://ftp.fr.debian.org/debian/pool/main/libs/libssh/",
        "package_name": "libssh-4_0.10.4-2_amd64.deb",
        "product": "libssh",
        "version": "0.10.4",
    },
    {
        "url": "http://ftp.fr.debian.org/debian/pool/main/libs/libssh/",
        "package_name": "libssh-4_0.10.4-2_arm64.deb",
        "product": "libssh",
        "version": "0.10.4",
    },
    {
        "url": "https://downloads.openwrt.org/releases/packages-19.07/x86_64/packages/",
        "package_name": "libssh_0.7.6-4_x86_64.ipk",
        "product": "libssh",
        "version": "0.7.6",
    },
]
