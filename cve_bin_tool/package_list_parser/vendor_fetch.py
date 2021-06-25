# Copyright (C) 2021 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later

import sqlite3
from os.path import join

from rich.progress import track

from cve_bin_tool.cvedb import DBNAME, DISK_LOCATION_DEFAULT


class VendorFetch:
    """
    This class is for reading vendor from the database for packages that doesn't have vendor info
    """

    def __init__(self) -> None:
        self.dbname: str = join(DISK_LOCATION_DEFAULT, DBNAME)

    def get_vendor_product_pairs(self, package_names):
        vendor_package_pairs = []
        query = """
        SELECT DISTINCT vendor FROM cve_range
        WHERE product=? 
        """
        # For python package checkers we don't need the progress bar running
        if type(package_names) != list:
            package_name = package_names  # Since package names will only have the 'package name' in it
            self.cursor.execute(query, [package_name])
            vendors = list(map(lambda x: x[0], self.cursor.fetchall()))
            for vendor in vendors:
                if vendor != "":
                    vendor_package_pairs.append(
                        {
                            "vendor": vendor,
                            "product": package_name,
                        }
                    )
        else:
            for package_name in track(
                package_names, description="Processing the given list...."
            ):
                self.cursor.execute(query, [package_name["name"].lower()])
                vendors = list(map(lambda x: x[0], self.cursor.fetchall()))
                for vendor in vendors:
                    if vendor != "":
                        vendor_package_pairs.append(
                            {
                                "vendor": vendor,
                                "product": package_name["name"],
                            }
                        )
        return vendor_package_pairs

    def __enter__(self):
        self.connection = sqlite3.connect(self.dbname)
        self.connection.row_factory = sqlite3.Row
        self.cursor = self.connection.cursor()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.cursor.close()
        self.connection.close()
