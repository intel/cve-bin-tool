# Copyright (C) 2023 Orange
# SPDX-License-Identifier: GPL-3.0-or-later

mapping_test_data = [
    {"product": "heimdal", "version": "7.5.0", "version_strings": ["Heimdal 7.5.0"]}
]
package_test_data = [
    {
        "url": "http://rpmfind.net/linux/opensuse/distribution/leap/15.4/repo/oss/aarch64/",
        "package_name": "libheimdal-7.7.0-bp154.1.43.aarch64.rpm",
        "product": "heimdal",
        "version": "7.7.0",
    },
    {
        "url": "http://ftp.fr.debian.org/debian/pool/main/h/heimdal/",
        "package_name": "libkrb5-26-heimdal_7.5.0+dfsg-3_amd64.deb",
        "product": "heimdal",
        "version": "7.5.0",
    },
    {
        "url": "https://dl-cdn.alpinelinux.org/alpine/v3.11/main/x86_64/",
        "package_name": "heimdal-7.7.0-r0.apk",
        "product": "heimdal",
        "version": "7.7.0",
    },
]
