# Copyright (C) 2024 Orange
# SPDX-License-Identifier: GPL-3.0-or-later

mapping_test_data = [
    {"product": "jasper", "version": "3.0.6", "version_strings": ["3.0.6\nlibjasper"]},
    {"product": "jasper", "version": "4.2.3", "version_strings": ["4.2.3\nJasPer"]},
]
package_test_data = [
    {
        "url": "http://rpmfind.net/linux/fedora/linux/releases/39/Everything/x86_64/os/Packages/j/",
        "package_name": "jasper-3.0.6-4.fc39.x86_64.rpm",
        "product": "jasper",
        "version": "3.0.6",
    },
    {
        "url": "https://eu.mirror.archlinuxarm.org/aarch64/extra/",
        "package_name": "jasper-4.2.4-1-aarch64.pkg.tar.xz",
        "product": "jasper",
        "version": "4.2.4",
        "other_products": ["gcc"],
    },
]
