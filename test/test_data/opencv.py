# Copyright (C) 2022 Orange
# SPDX-License-Identifier: GPL-3.0-or-later

mapping_test_data = [
    {"product": "opencv", "version": "4.5.5", "version_strings": ["opencv-4.5.5"]}
]
package_test_data = [
    {
        "url": "http://rpmfind.net/linux/opensuse/distribution/leap/15.4/repo/oss/aarch64/",
        "package_name": "libopencv405-4.5.5-150400.1.28.aarch64.rpm",
        "product": "opencv",
        "version": "4.5.5",
    },
    {
        "url": "http://rpmfind.net/linux/opensuse/distribution/leap/15.4/repo/oss/ppc64le/",
        "package_name": "libopencv405-4.5.5-150400.1.28.ppc64le.rpm",
        "product": "opencv",
        "version": "4.5.5",
    },
    {
        "url": "http://ftp.fr.debian.org/debian/pool/main/o/opencv/",
        "package_name": "libopencv-calib3d2.4v5_2.4.9.1+dfsg1-2_amd64.deb",
        "product": "opencv",
        "version": "2.4.9.1",
    },
    {
        "url": "http://ftp.fr.debian.org/debian/pool/main/o/opencv/",
        "package_name": "libopencv-calib3d2.4v5_2.4.9.1+dfsg1-2_arm64.deb",
        "product": "opencv",
        "version": "2.4.9.1",
    },
    {
        "url": "https://downloads.openwrt.org/releases/packages-19.07/x86_64/packages/",
        "package_name": "opencv_4.1.1-1_x86_64.ipk",
        "product": "opencv",
        "version": "4.1.1",
    },
]
