# Copyright (C) 2022 Orange
# SPDX-License-Identifier: GPL-3.0-or-later

mapping_test_data = [
    {"product": "git", "version": "1.8.5.3", "version_strings": ["git/1.8.5.3"]},
    {"product": "git", "version": "2.1.4", "version_strings": ["git/2.1.4"]},
]
package_test_data = [
    {
        "url": "https://kojipkgs.fedoraproject.org/packages/git/1.8.5.3/2.fc21/x86_64/",
        "package_name": "git-1.8.5.3-2.fc21.x86_64.rpm",
        "product": "git",
        "version": "1.8.5.3",
    },
    {
        "url": "http://ftp.fr.debian.org/debian/pool/main/g/git/",
        "package_name": "git_2.1.4-2.1+deb8u6_amd64.deb",
        "product": "git",
        "version": "2.1.4",
    },
    {
        "url": "https://downloads.openwrt.org/releases/packages-19.07/x86_64/packages/",
        "package_name": "git_2.26.3-1_x86_64.ipk",
        "product": "git",
        "version": "2.26.3",
    },
]
