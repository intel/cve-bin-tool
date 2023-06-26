# Copyright (C) 2022 Orange
# SPDX-License-Identifier: GPL-3.0-or-later

mapping_test_data = [
    {"product": "perl", "version": "5.36.0", "version_strings": ["perl/5.36.0"]},
    {
        "product": "perl",
        "version": "5.28.1",
        "version_strings": ["PERL_INTERNAL_RAND_SEED\nv5.28.1"],
    },
]
package_test_data = [
    {
        "url": "http://rpmfind.net/linux/opensuse/ports/aarch64/tumbleweed/repo/oss/aarch64/",
        "package_name": "perl-5.36.0-3.5.aarch64.rpm",
        "product": "perl",
        "version": "5.36.0",
    },
    {
        "url": "http://ftp.fr.debian.org/debian/pool/main/p/perl/",
        "package_name": "perl-base_5.20.2-3+deb8u11_amd64.deb",
        "product": "perl",
        "version": "5.20.2",
    },
    {
        "url": "https://downloads.openwrt.org/releases/packages-19.07/x86_64/packages/",
        "package_name": "perl_5.28.1-4_x86_64.ipk",
        "product": "perl",
        "version": "5.28.1",
    },
]
