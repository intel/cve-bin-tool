# Copyright (C) 2022 Orange
# SPDX-License-Identifier: GPL-3.0-or-later

mapping_test_data = [
    {
        "product": "asterisk",
        "version": "18.12.1",
        "version_strings": ["asterisk-18.12.1"],
    },
    {
        "product": "asterisk",
        "version": "16.16.1",
        "version_strings": ["ast_uuid_init\n16.16.1"],
    },
]
package_test_data = [
    {
        "url": "http://rpmfind.net/linux/fedora/linux/development/rawhide/Everything/aarch64/os/Packages/a/",
        "package_name": "asterisk-18.12.1-1.fc37.1.aarch64.rpm",
        "product": "asterisk",
        "version": "18.12.1",
    },
    {
        "url": "http://rpmfind.net/linux/fedora/linux/development/rawhide/Everything/x86_64/os/Packages/a/",
        "package_name": "asterisk-18.12.1-1.fc37.1.i686.rpm",
        "product": "asterisk",
        "version": "18.12.1",
    },
    {
        "url": "http://ftp.de.debian.org/debian/pool/main/a/asterisk/",
        "package_name": "asterisk_16.16.1~dfsg-1+deb11u1_arm64.deb",
        "product": "asterisk",
        "version": "16.16.1",
    },
    {
        "url": "https://downloads.openwrt.org/releases/22.03.0/packages/aarch64_generic/telephony/",
        "package_name": "asterisk_18.11.2-4_aarch64_generic.ipk",
        "product": "asterisk",
        "version": "18.11.2",
    },
]
