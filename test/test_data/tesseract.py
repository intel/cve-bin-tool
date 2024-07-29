# Copyright (C) 2023 Orange
# SPDX-License-Identifier: GPL-3.0-or-later

mapping_test_data = [
    {"product": "tesseract", "version": "4.0.0", "version_strings": ["tesseract 4.0.0"]}
]
package_test_data = [
    {
        "url": "http://rpmfind.net/linux/fedora/linux/development/rawhide/Everything/aarch64/os/Packages/t/",
        "package_name": "tesseract-5.3.3-1.fc40.aarch64.rpm",
        "product": "tesseract",
        "version": "5.3.3",
    },
    {
        "url": "http://ftp.fr.debian.org/debian/pool/main/t/tesseract/",
        "package_name": "libtesseract4_4.0.0-2_amd64.deb",
        "product": "tesseract",
        "version": "4.0.0",
    },
    {
        "url": "https://downloads.openwrt.org/releases/21.02.0/packages/x86_64/packages/",
        "package_name": "tesseract_4.0.0-2_x86_64.ipk",
        "product": "tesseract",
        "version": "4.0.0",
    },
]
