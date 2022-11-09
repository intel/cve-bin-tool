# Copyright (C) 2022 Orange
# SPDX-License-Identifier: GPL-3.0-or-later

mapping_test_data = [
    {
        "product": "spice",
        "version": "0.14.2",
        "version_strings": [
            "SPICE_SERVER_0.14.2\nGLIBC_2.17",
        ],
    }
]
package_test_data = [
    {
        "url": "https://www.rpmfind.net/linux/opensuse/ports/aarch64/distribution/leap/15.2/repo/oss/aarch64/",
        "package_name": "libspice-server1-0.14.2-lp152.1.1.aarch64.rpm",
        "product": "spice",
        "version": "0.14.2",
    },
    {
        "url": "http://ftp.fr.debian.org/debian/pool/main/s/spice/",
        "package_name": "libspice-server1_0.12.5-1+deb8u5_amd64.deb",
        "product": "spice",
        "version": "0.12.5",
    },
    {
        "url": "http://ftp.fr.debian.org/debian/pool/main/s/spice/",
        "package_name": "libspice-server1_0.12.5-1+deb8u5_i386.deb",
        "product": "spice",
        "version": "0.12.5",
    },
]
