# Copyright (C) 2021 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later

mapping_test_data = [
    {"product": "openssh", "version": "6.8p1", "version_strings": ["OpenSSH_6.8p1"]}
]
package_test_data = [
    {
        "url": "https://kojipkgs.fedoraproject.org/packages/openssh/6.8p1/1.1.fc23/x86_64/",
        "package_name": "openssh-clients-6.8p1-1.1.fc23.x86_64.rpm",
        "product": "openssh",
        "version": "6.8p1",
    },
    {
        "url": "http://ftp.fr.debian.org/debian/pool/main/o/openssh/",
        "package_name": "openssh-client_6.7p1-5+deb8u4_amd64.deb",
        "product": "openssh",
        "version": "6.7p1",
    },
    {
        "url": "https://downloads.openwrt.org/releases/packages-19.07/x86_64/packages/",
        "package_name": "openssh-client_8.0p1-1_x86_64.ipk",
        "product": "openssh",
        "version": "8.0p1",
    },
]
