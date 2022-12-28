# Copyright (C) 2022 Orange
# SPDX-License-Identifier: GPL-3.0-or-later

mapping_test_data = [
    {"product": "miniupnpc", "version": "2.1", "version_strings": ["MiniUPnPc/2.1"]},
    {
        "product": "miniupnpc",
        "version": "2.2.4",
        "version_strings": ["MiniUPnPc/2.2.4"],
    },
]
package_test_data = [
    {
        "url": "https://kojipkgs.fedoraproject.org/packages/miniupnpc/2.1/1.fc30/aarch64/",
        "package_name": "miniupnpc-2.1-1.fc30.aarch64.rpm",
        "product": "miniupnpc",
        "version": "2.1",
    },
    {
        "url": "http://ftp.de.debian.org/debian/pool/main/m/miniupnpc/",
        "package_name": "libminiupnpc17_2.2.3-1+b1_amd64.deb",
        "product": "miniupnpc",
        "version": "2.2.3",
    },
    {
        "url": "https://downloads.openwrt.org/releases/packages-21.02/x86_64/packages/",
        "package_name": "libminiupnpc_2.2.1-1_x86_64.ipk",
        "product": "miniupnpc",
        "version": "2.2.1",
    },
]
