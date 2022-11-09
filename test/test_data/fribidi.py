# Copyright (C) 2022 Orange
# SPDX-License-Identifier: GPL-3.0-or-later

mapping_test_data = [
    {"product": "fribidi", "version": "0.10.7", "version_strings": ["fribidi 0.10.7"]},
    {
        "product": "fribidi",
        "version": "0.19.6",
        "version_strings": ["(GNU FriBidi) 0.19.6"],
    },
]
package_test_data = [
    {
        "url": "https://kojipkgs.fedoraproject.org/packages/fribidi/0.10.7/6.fc7/x86_64/",
        "package_name": "fribidi-0.10.7-6.fc7.x86_64.rpm",
        "product": "fribidi",
        "version": "0.10.7",
    },
    {
        "url": "http://ftp.fr.debian.org/debian/pool/main/f/fribidi/",
        "package_name": "libfribidi0_0.19.6-3_amd64.deb",
        "product": "fribidi",
        "version": "0.19.6",
    },
    {
        "url": "http://ftp.fr.debian.org/debian/pool/main/f/fribidi/",
        "package_name": "libfribidi0_1.0.8-2.1_mips64el.deb",
        "product": "fribidi",
        "version": "1.0.8",
    },
]
