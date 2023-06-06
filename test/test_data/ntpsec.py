# Copyright (C) 2022 Orange
# SPDX-License-Identifier: GPL-3.0-or-later

mapping_test_data = [
    {
        "product": "ntpsec",
        "version": "1.1.3",
        "version_strings": ["1.1.3 2019-11-18T06:04:00Z\nntpd ntpsec"],
    },
]

package_test_data = [
    {
        "url": "http://rpmfind.net/linux/fedora/linux/development/rawhide/Everything/aarch64/os/Packages/n/",
        "package_name": "ntpsec-1.2.1-9.fc37.aarch64.rpm",
        "product": "ntpsec",
        "version": "1.2.1",
    },
    {
        "url": "http://rpmfind.net/linux/fedora/linux/development/rawhide/Everything/x86_64/os/Packages/n/",
        "package_name": "ntpsec-1.2.1-9.fc37.i686.rpm",
        "product": "ntpsec",
        "version": "1.2.1",
    },
    {
        "url": "http://ftp.fr.debian.org/debian/pool/main/n/ntpsec/",
        "package_name": "ntpsec_1.1.3+dfsg1-2+deb10u1_amd64.deb",
        "product": "ntpsec",
        "version": "1.1.3",
    },
]
