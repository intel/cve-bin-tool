# Copyright (C) 2021 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later

mapping_test_data = [
    {
        "product": "glibc",
        "version": "2.31",
        "version_strings": [
            "GLIBC 2.31) ",
            "The following command substitution is needed to make ldd work in SELinux",
            "environments where the RTLD might not have permission to write to the",
        ],
    }
]
package_test_data = [
    # works locally, no luck in CI
    # {
    #    "url": "https://kojipkgs.fedoraproject.org/packages/glibc/2.28/39.fc29/i686/",
    #    "package_name": "glibc-2.28-39.fc29.i686.rpm",
    #    "product": "glibc",
    #    "version": "2.28",
    #    "other_products": ["gcc"],
    # },
    {
        "url": "https://rpmfind.net/linux/fedora/linux/releases/33/Everything/x86_64/os/Packages/g/",
        "package_name": "glibc-2.32-1.fc33.i686.rpm",
        "product": "glibc",
        "version": "2.32",
        "other_products": ["gcc"],
    },
    {
        "url": "http://ftp.fr.debian.org/debian/pool/main/g/glibc/",
        "package_name": "libc-bin_2.19-18+deb8u10_amd64.deb",
        "product": "glibc",
        "version": "2.19",
    },
    {
        "url": "http://ftp.fr.debian.org/debian/pool/main/g/glibc/",
        "package_name": "libc6-amd64_2.24-11+deb9u4_i386.deb",
        "product": "glibc",
        "version": "2.24",
    },
]
