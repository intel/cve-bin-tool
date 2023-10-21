# Copyright (C) 2021 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later

mapping_test_data = [
    {"product": "tcpdump", "version": "4.9.0", "version_strings": ["tcpdump-4.9.0"]},
    {
        "product": "tcpdump",
        "version": "4.9.2",
        "version_strings": ["4.9.2\nlookup_protoid"],
    },
    {
        "product": "tcpdump",
        "version": "4.9.3",
        "version_strings": ["4.9.3\nlookup_emem"],
    },
    {
        "product": "tcpdump",
        "version": "4.9.3",
        "version_strings": ["4.9.3\n0123456789abcdeflookup_emem"],
    },
    {
        "product": "tcpdump",
        "version": "4.9.2",
        "version_strings": ["Running\n4.9.2\n0123456789"],
    },
    {"product": "tcpdump", "version": "4.1.1", "version_strings": ["tcpdump\n4.1.1"]},
    {
        "product": "tcpdump",
        "version": "4.99.4",
        "version_strings": ["version 4.99.4\nSMI-library"],
    },
]
package_test_data = [
    {
        "url": "https://kojipkgs.fedoraproject.org/packages/tcpdump/4.9.1/1.fc27/x86_64/",
        "package_name": "tcpdump-4.9.1-1.fc27.x86_64.rpm",
        "product": "tcpdump",
        "version": "4.9.1",
    },
    {
        "url": "http://ftp.fr.debian.org/debian/pool/main/t/tcpdump/",
        "package_name": "tcpdump_4.9.2-1~deb8u1_amd64.deb",
        "product": "tcpdump",
        "version": "4.9.2",
    },
    {
        "url": "http://ftp.fr.debian.org/debian/pool/main/t/tcpdump/",
        "package_name": "tcpdump_4.9.3-1~deb10u2_arm64.deb",
        "product": "tcpdump",
        "version": "4.9.3",
    },
    {
        "url": "http://ftp.fr.debian.org/debian/pool/main/t/tcpdump/",
        "package_name": "tcpdump_4.99.4-3_mips64el.deb",
        "product": "tcpdump",
        "version": "4.99.4",
    },
    {
        "url": "https://downloads.openwrt.org/releases/packages-19.07/x86_64/base/",
        "package_name": "tcpdump_4.9.3-3_x86_64.ipk",
        "product": "tcpdump",
        "version": "4.9.3",
    },
]
