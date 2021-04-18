# Copyright (C) 2021 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later


"""
CVE checker for kerberos (CLI/library)

References:
https://www.cvedetails.com/vulnerability-list/vendor_id-42/product_id-61/MIT-Kerberos.html
"""
from cve_bin_tool.checkers import Checker


class KerberosChecker(Checker):
    CONTAINS_PATTERNS = [r"KRB5_BRAND: "]
    FILENAME_PATTERNS = [r"kerberos"]
    VERSION_PATTERNS = [
        r"KRB5_BRAND: krb5-(\d+\.\d+\.?\d?)-final",
        r"kerberos 5[_-][apl-]*(1+\.[0-9]+(\.[0-9]+)*)",
    ]
    VENDOR_PRODUCT = [("mit", "kerberos"), ("mit", "kerberos_5")]

    def get_version(self, lines, filename):
        version_info = super().get_version(lines, filename)

        # currently we're only detecting kerberos 5, so return a double-version_info list
        # if we ever detect kerberos that's not 5, this if statement will change
        if "is_or_contains" in version_info:
            version_info5 = [dict(), dict()]
            version_info5[0] = version_info
            version_info5[1] = dict()
            version_info5[1]["is_or_contains"] = version_info["is_or_contains"]
            version_info5[1]["productname"] = "kerberos_5"

            # strip the leading "5-" off the version for 'kerberos_5' if there is one
            # or conversely, add one to the 'kerberos' listing if there isn't
            if version_info["version"][:2] == "5-":
                version_info5[1]["version"] = version_info["version"][2:]
            else:
                version_info5[1]["version"] = version_info["version"]
                version_info5[0]["version"] = "5-{}".format(version_info["version"])
            return version_info5

        return version_info
