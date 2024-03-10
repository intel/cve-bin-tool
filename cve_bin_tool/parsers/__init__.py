# Copyright (C) 2022 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later

from packageurl import PackageURL

from cve_bin_tool.util import ProductInfo, ScanInfo

__all__ = [
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
        if vendor_package_pair != []:
            # To handle multiple vendors, return all combinations of product/vendor mappings
            for v in vendor_package_pair:
                vendor = v["vendor"]
                self.logger.debug(f"{file_path} {product} {version} by {vendor}")
                vendorlist.append(
                    ScanInfo(ProductInfo(vendor, product, version), file_path)
                )
        else:
            # Add entry
            vendorlist.append(
                ScanInfo(ProductInfo("UNKNOWN", product, version), file_path)
            )
        return vendorlist

    def generate_purl(self, product, version, vendor, qualifier={}, subpath=None):
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
