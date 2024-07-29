# Copyright (C) 2022 Orange
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import annotations

mapping_test_data: list[dict] = []
package_test_data = [
    {
        "url": "http://rpmfind.net/linux/opensuse/distribution/leap/15.5/repo/oss/aarch64/",
        "package_name": "grub2-2.06-150400.11.5.2.aarch64.rpm",
        "product": "grub2",
        "version": "2.06",
        "other_products": ["zstandard"],
    },
    {
        "url": "http://rpmfind.net/linux/opensuse/distribution/leap/15.5/repo/oss/ppc64le/",
        "package_name": "grub2-2.06-150400.11.5.2.ppc64le.rpm",
        "product": "grub2",
        "version": "2.06",
        "other_products": ["zstandard"],
    },
    {
        "url": "http://ftp.fr.debian.org/debian/pool/main/g/grub2/",
        "package_name": "grub-common_2.02+dfsg1-20+deb10u1_amd64.deb",
        "product": "grub2",
        "version": "2.02",
    },
    {
        "url": "http://ftp.fr.debian.org/debian/pool/main/g/grub2/",
        "package_name": "grub-common_2.02+dfsg1-20+deb10u1_arm64.deb",
        "product": "grub2",
        "version": "2.02",
    },
]
