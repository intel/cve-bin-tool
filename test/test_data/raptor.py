# Copyright (C) 2023 Orange
# SPDX-License-Identifier: GPL-3.0-or-later

mapping_test_data = [
    {
        "product": "raptor_rdf_syntax_library",
        "version": "2.0.15",
        "version_strings": ["rapper-2.0.15"],
    },
    {
        "product": "raptor_rdf_syntax_library",
        "version": "1.4.21",
        "version_strings": ["1.4.21\nhttp://librdf.org/raptor"],
    },
]
package_test_data = [
    {
        "url": "http://rpmfind.net/linux/opensuse/distribution/leap/15.5/repo/oss/aarch64/",
        "package_name": "raptor-2.0.15-150200.9.12.1.aarch64.rpm",
        "product": "raptor_rdf_syntax_library",
        "version": "2.0.15",
    },
    {
        "url": "http://ftp.fr.debian.org/debian/pool/main/r/raptor/",
        "package_name": "libraptor1_1.4.21-11+b1_amd64.deb",
        "product": "raptor_rdf_syntax_library",
        "version": "1.4.21",
    },
    {
        "url": "http://ftp.fr.debian.org/debian/pool/main/r/raptor2/",
        "package_name": "libraptor2-0_2.0.14-1+b1_amd64.deb",
        "product": "raptor_rdf_syntax_library",
        "version": "2.0.14",
    },
]
