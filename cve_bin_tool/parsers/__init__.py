# Copyright (C) 2022 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import annotations

import sqlite3

from packageurl import PackageURL

from cve_bin_tool.cvedb import DBNAME, DISK_LOCATION_DEFAULT
from cve_bin_tool.error_handler import CVEDBError
from cve_bin_tool.util import ProductInfo, ScanInfo, decode_cpe23

__all__ = [
    "parse",
    "Parser",
    "java",
    "javascript",
    "python",
    "r",
    "ruby",
    "rust",
    "go",
    "swift",
    "php",
    "perl",
    "dart",
    "env",
]


class Parser:
    """
    A class to parse and process data related to known software components,
    typically generated for or by programming languages.

    Attributes:
        cve_db (CVE_DB): An instance of CVE_DB used for CVE database operations.
        logger (Logger): An instance of Logger used for logging.
        filename (str): The filename of the data to be processed.
    """

    def __init__(self, cve_db, logger):
        """Initializes a Parser object."""
        self.cve_db = cve_db
        self.logger = logger
        self.filename = ""
        self.purl_pkg_type = "default"
        self.connection: sqlite3.Connection | None = None
        self.dbpath = DISK_LOCATION_DEFAULT / DBNAME

    def run_checker(self, filename):
        """
        Runs the checker for the specified filename.

        Args:
            filename (str): The filename to be checked.
        """
        pass

    def find_vendor(self, product, version):
        """
        Finds the vendor for the given product and version.

        Args:
            product (str): The product name.
            version (str): The product version.

        Returns:
            list: A list of ScanInfo objects containing vendor information.
        """
        vendor_package_pair = self.cve_db.get_vendor_product_pairs(product)
        vendorlist: list[ScanInfo] = []
        file_path = self.filename
        location = file_path
        if vendor_package_pair != []:
            # To handle multiple vendors, return all combinations of product/vendor mappings
            for v in vendor_package_pair:
                vendor = v["vendor"]
                location = v.get("location", self.filename)
                self.logger.debug(f"{file_path} {product} {version} by {vendor}")
                vendorlist.append(
                    ScanInfo(ProductInfo(vendor, product, version, location), file_path)
                )
        else:
            # Add entry
            vendorlist.append(
                ScanInfo(ProductInfo("UNKNOWN", product, version, location), file_path)
            )
        return vendorlist

    def generate_purl(self, product, vendor="", version="", qualifier={}, subpath=None):
        """Generate purl string based on various components."""
        purl = PackageURL(
            type=self.purl_pkg_type,
            namespace=vendor,
            name=product,
            version=version,
            qualifiers=qualifier,
            subpath=subpath,
        )
        return purl

    def get_vendor(self, purl, product, version):
        """Returns the finalised vendor after utilising various mechanisms."""
        vendor, result = self.find_vendor_from_purl(purl, version)

        if not result:
            vendor = self.find_vendor(product, version)

        return self.mismatch(purl, vendor)

    def find_vendor_from_purl(self, purl, ver) -> tuple[list[ScanInfo], bool]:
        """
        Finds the vendor information for a given PackageURL (purl) and version from the database.

        This method queries the database to retrieve Common Platform Enumeration (CPE) data associated with the given purl.
        It then decodes the CPE data to extract vendor, product, and version information. If the version matches the provided
        version, it constructs a ScanInfo object for each matching entry and returns a list of these objects.
        """
        try:
            purl = purl.to_dict()
            param1 = f"pkg:{purl['type']}/{purl['name']}"
            param2 = f"pkg:{purl['type']}/%/{purl['name']}"

            query = """
                SELECT cpe from purl2cpe WHERE purl LIKE ?
                UNION
                SELECT cpe from purl2cpe WHERE purl LIKE ?
            """
            cursor = self.db_open_and_get_cursor()
            cursor.execute(query, (param1, param2))
            cpeList = cursor.fetchall()
            vendorlist: list[ScanInfo] = []
            vendors = set()

            if cpeList != []:
                for item in cpeList:
                    vendor, _, _ = decode_cpe23(str(item))
                    vendors.add((vendor, purl["name"]))
            else:
                return vendorlist, False

            for vendor, product in vendors:
                purl_with_ver = self.generate_purl(product, vendor, ver)
                vendorlist.append(
                    ScanInfo(
                        ProductInfo(
                            vendor,
                            product,
                            ver,
                            self.filename,
                            purl_with_ver,
                        ),
                        self.filename,
                    )
                )

            return vendorlist, True
        except Exception as e:
            self.logger.debug(
                f"Error occurred: {e} - Unable to access purl2cpe database."
            )
            return [], False

    def mismatch(self, purl, vendorlist) -> list[ScanInfo]:
        """
        Modifies invalid vendors associated with a given PURL using the mismatch database.

        It queries the database for vendors associated with the PURL and filters the input 'vendorlist'
        accordingly:

        - If a vendor from 'vendorlist' is found in the database (valid vendor), it is added directly
          to 'vendorlist_filtered'.
        - If a vendor from 'vendorlist' is not found in the database (invalid vendor), a new ScanInfo
          object is created with the vendor marked as 'UNKNOWN' and added to 'vendorlist_filtered'.

        """
        try:
            purl = purl.to_dict()
            param = f"pkg:{purl['type']}/{purl['name']}"
            query = """
                SELECT vendor FROM mismatch WHERE purl LIKE ?
            """
            vendorlist_filtered: list[ScanInfo] = []
            cursor = self.db_open_and_get_cursor()
            cursor.execute(query, (param,))

            invalidVendorList = [i[0] for i in cursor.fetchall()]

            for item in vendorlist:
                if item.product_info.vendor not in invalidVendorList:
                    vendorlist_filtered.append(item)

            if len(vendorlist_filtered) == 0:
                vendorlist_filtered.append(
                    ScanInfo(
                        ProductInfo(
                            "UNKNOWN",
                            item.product_info.product,
                            item.product_info.version,
                            item.file_path,
                        ),
                        item.file_path,
                    )
                )
            return vendorlist_filtered
        except Exception as e:
            self.logger.debug(f"error: {e} - Unable to access mismatch database.")
            return vendorlist

    def db_open_and_get_cursor(self) -> sqlite3.Cursor:
        """Opens connection to sqlite database, returns cursor object."""

        if not self.connection:
            self.connection = sqlite3.connect(self.dbpath)
        if self.connection is not None:
            cursor = self.connection.cursor()
        if cursor is None:
            self.logger.error("Database cursor does not exist")
            raise CVEDBError
        return cursor
