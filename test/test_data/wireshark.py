# Copyright (C) 2021 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later

mapping_test_data = [
    {
        "product": "wireshark",
        "version": "1.10.12",
        "version_strings": ["Wireshark 1.10.12."],
    }
]
package_test_data = [
    {
        "url": "https://kojipkgs.fedoraproject.org/packages/wireshark/1.10.13/1.fc20/x86_64/",
        "package_name": "wireshark-1.10.13-1.fc20.x86_64.rpm",
        "product": "wireshark",
        "version": "1.10.13",
        "other_products": ["gnutls"],
    },
    {
        "url": "http://mirror.centos.org/centos/7/os/x86_64/Packages/",
        "package_name": "wireshark-1.10.14-25.el7.i686.rpm",
        "product": "wireshark",
        "version": "1.10.14",
        "other_products": ["gnutls"],
    },
    {
        "url": "https://download-ib01.fedoraproject.org/pub/fedora/linux/releases/34/Everything/aarch64/os/Packages/w/",
        "package_name": "wireshark-3.4.4-1.fc34.aarch64.rpm",
        "product": "wireshark",
        "version": "3.4.4",
    },
    {
        "url": "http://mirror.centos.org/centos/8/AppStream/x86_64/os/Packages/",
        "package_name": "wireshark-2.6.2-12.el8.x86_64.rpm",
        "product": "wireshark",
        "version": "2.6.2",
    },
    {
        "url": "http://ftp.fr.debian.org/debian/pool/main/w/wireshark/",
        "package_name": "libwireshark16_4.0.3-1_amd64.deb",
        "product": "wireshark",
        "version": "4.0.3",
    },
]
