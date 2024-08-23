# Copyright (C) 2024 Orange
# SPDX-License-Identifier: GPL-3.0-or-later

mapping_test_data = [
    {
        "product": "ghostscript",
        "version": "9.27",
        "version_strings": ["ghostscript/9.27"],
    },
    {
        "product": "ghostscript",
        "version": "10.03.1",
        "version_strings": ["10.03.1\nghostscript"],
    },
]
package_test_data = [
    {
        "url": "http://ftp.fr.debian.org/debian/pool/main/g/ghostscript/",
        "package_name": "libgs9_9.27~dfsg-2+deb10u5_amd64.deb",
        "product": "ghostscript",
        "version": "9.27",
    },
    {
        "url": "https://eu.mirror.archlinuxarm.org/aarch64/extra/",
        "package_name": "ghostscript-10.03.1-1-aarch64.pkg.tar.xz",
        "product": "ghostscript",
        "version": "10.03.1",
        "other_products": ["gcc"],
    },
]
