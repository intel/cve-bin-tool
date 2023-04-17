# Copyright (C) 2023 Orange
# SPDX-License-Identifier: GPL-3.0-or-later

mapping_test_data = [
    {
        "product": "harfbuzz",
        "version": "7.0.0",
        "version_strings": ["HB_OPTIONS\nuniscribe-bug-compatible\ninvalid\n7.0.0"],
    },
    {"product": "harfbuzz", "version": "1.4.2", "version_strings": ["1.4.2\nHarfBuzz"]},
]
package_test_data = [
    {
        "url": "http://mirror.centos.org/altarch/7/os/aarch64/Packages/",
        "package_name": "harfbuzz-1.7.5-2.el7.aarch64.rpm",
        "product": "harfbuzz",
        "version": "1.7.5",
    },
    {
        "url": "http://rpmfind.net/linux/fedora/linux/development/rawhide/Everything/aarch64/os/Packages/h/",
        "package_name": "harfbuzz-7.0.0-2.fc39.aarch64.rpm",
        "product": "harfbuzz",
        "version": "7.0.0",
    },
    {
        "url": "http://ftp.fr.debian.org/debian/pool/main/h/harfbuzz/",
        "package_name": "libharfbuzz0b_0.9.35-2_amd64.deb",
        "product": "harfbuzz",
        "version": "0.9.35",
    },
    {
        "url": "http://ftp.fr.debian.org/debian/pool/main/h/harfbuzz/",
        "package_name": "libharfbuzz-bin_1.4.2-1_amd64.deb",
        "product": "harfbuzz",
        "version": "1.4.2",
    },
    {
        "url": "http://ftp.fr.debian.org/debian/pool/main/h/harfbuzz/",
        "package_name": "libharfbuzz0b_6.0.0+dfsg-3_amd64.deb",
        "product": "harfbuzz",
        "version": "6.0.0",
    },
]
