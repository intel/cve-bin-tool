# Copyright (C) 2021 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later

mapping_test_data = [
    {
        "product": "poppler",
        "version": "21.01.0",
        "version_strings": [
            r"Unknown CID font collection, please report to poppler bugzilla.",
            r"/builddir/build/BUILD/poppler-21.01.0/poppler/Object.h",
            r"/builddir/build/BUILD/poppler-21.01.0/poppler/Annot.cc",
            r"/builddir/build/BUILD/poppler-21.01.0/poppler/Array.cc",
            r"/builddir/build/BUILD/poppler-21.01.0/poppler/GfxState.cc",
            r"/builddir/build/BUILD/poppler-21.01.0/poppler/StructElement.cc",
            r"/builddir/build/BUILD/poppler-21.01.0/poppler/StructTreeRoot.cc",
            r"/builddir/build/BUILD/poppler-21.01.0/splash/Splash.cc",
        ],
    },
    {
        "product": "poppler",
        "version": "0.82.0",
        "version_strings": [
            r"Unknown CID font collection, please report to poppler bugzilla.",
            r"/home/buildozer/aports/main/poppler/src/poppler-0.82.0/poppler/Annot.cc",
            r"$@/home/buildozer/aports/main/poppler/src/poppler-0.82.0/poppler/Object.h",
            r"/home/buildozer/aports/main/poppler/src/poppler-0.82.0/poppler/Array.cc",
            r"/home/buildozer/aports/main/poppler/src/poppler-0.82.0/poppler/GfxState.cc",
            r"/home/buildozer/aports/main/poppler/src/poppler-0.82.0/poppler/StructTreeRoot.cc",
            r"/home/buildozer/aports/main/poppler/src/poppler-0.82.0/poppler/StructElement.cc",
            r"/home/buildozer/aports/main/poppler/src/poppler-0.82.0/splash/Splash.cc",
        ],
    },
]
package_test_data = [
    {
        "url": "https://download-ib01.fedoraproject.org/pub/fedora/linux/releases/34/Everything/x86_64/os/Packages/p/",
        "package_name": "poppler-21.01.0-6.fc34.x86_64.rpm",
        "product": "poppler",
        "version": "21.01.0",
    },
    {
        "url": "http://dl-cdn.alpinelinux.org/alpine/v3.11/main/x86_64/",
        "package_name": "poppler-0.82.0-r1.apk",
        "product": "poppler",
        "version": "0.82.0",
    },
]
