# Copyright (C) 2023 Orange
# SPDX-License-Identifier: GPL-3.0-or-later

mapping_test_data = [
    {
        "product": "qpdf",
        "version": "8.4.0",
        "version_strings": ["QPDF decoding error warning\n8.4.0"],
    },
    {"product": "qpdf", "version": "11.5.0", "version_strings": ["qpdf-11.5.0"]},
]
package_test_data = [
    {
        "url": "http://rpmfind.net/linux/fedora/linux/development/rawhide/Everything/aarch64/os/Packages/q/",
        "package_name": "qpdf-11.5.0-1.fc39.aarch64.rpm",
        "product": "qpdf",
        "version": "11.5.0",
    },
    {
        "url": "http://ftp.fr.debian.org/debian/pool/main/q/qpdf/",
        "package_name": "libqpdf21_8.4.0-2_amd64.deb",
        "product": "qpdf",
        "version": "8.4.0",
    },
]
