# Copyright (C) 2021 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later

"""Utility classes for the CVE Binary Tool"""

from __future__ import annotations

import fnmatch
import os
import re
import sys
from enum import Enum
from pathlib import Path
from typing import DefaultDict, Iterator, List, NamedTuple, Pattern, Set, Union

import requests
from packageurl import PackageURL

from cve_bin_tool.log import LOGGER


class OrderedEnum(Enum):
    """
    An enumeration that supports order comparisons.

    Each member of the enumeration can be compared to others. The comparison is based on the value of the enumeration member.
    """

    def __ge__(self, other: OrderedEnum) -> bool:
        """
        Check if this member is greater than or equal to the other member.

        Args:
            other (OrderedEnum): The other member to compare with.

        Returns:
            bool: True if this member is greater than or equal to the other member, False otherwise.
        """
        if self.__class__ is other.__class__:
            return self.value >= other.value
        return NotImplemented

    def __gt__(self, other: OrderedEnum) -> bool:
        """
        Check if this member is greater than the other member.

        Args:
            other (OrderedEnum): The other member to compare with.

        Returns:
            bool: True if this member is greater than the other member, False otherwise.
        """
        if self.__class__ is other.__class__:
            return self.value > other.value
        return NotImplemented

    def __le__(self, other: OrderedEnum) -> bool:
        """
        Check if this member is less than or equal to the other member.

        Args:
            other (OrderedEnum): The other member to compare with.

        Returns:
            bool: True if this member is greater than or equal to the other member, False otherwise.
        """
        if self.__class__ is other.__class__:
            return self.value <= other.value
        return NotImplemented

    def __lt__(self, other: OrderedEnum) -> bool:
        """
        Check if this member is less than the other member.
        Args:
            other (OrderedEnum): The other member to compare with.
        Returns:
            bool: True if this member is less than the other member, False otherwise.
        """
        if self.__class__ is other.__class__:
            return self.value < other.value
        return NotImplemented


class Remarks(OrderedEnum):
    """
    An enumeration of remarks.

    Each member of the enumeration represents a specific remark with a unique value.
    """

    NewFound = 1, "New", "1", "NewFound", "n", "N"
    Unexplored = 2, "Unexplored", "2", "Unexplored", "u", "U", ""
    Confirmed = 3, "Confirmed", "3", "Confirmed", "c", "C"
    Mitigated = 4, "Mitigated", "4", "Mitigated", "m", "M"
    FalsePositive = 5, "False Positive", "5", "FalsePositive", "f", "F"
    NotAffected = 6, "Not Affected", "6", "NotAffected", "i", "I"

    def __new__(cls, value: int, string: str, *aliases: str) -> Remarks:
        """
        Return a new instance of the Remarks enumeration.
        """
        obj = object.__new__(cls)
        obj._value_ = value
        for alias in aliases:
            cls._value2member_map_[alias] = obj
        string_map = getattr(cls, "string_map", {})
        string_map[value] = string
        cls.string_map = string_map
        return obj

    def __str__(self):
        """
        Returns a human-readable string of the enumeration value
        """
        return self.string_map[self.value]


class CVE(NamedTuple):
    """
    Class to hold CVE information
    attributes:
        cve_number: str
        severity: str
        remarks: Remarks
        description: str
        comments: str
        score: float
        cvss_version: int
        cvss_vector: str
        data_source: str
        last_modified: str
        metric: dict[str, list[float | str]]
        justification: str | None
        response: list[str]
    """

    cve_number: str
    severity: str
    remarks: Remarks = Remarks.NewFound
    description: str = ""
    comments: str = ""
    score: float = 0
    cvss_version: int = 0
    cvss_vector: str = ""
    data_source: str = ""
    last_modified: str = ""
    metric: dict[str, list[float | str]] = {}
    justification: str | None = None
    response: list[str] = []


class ProductInfo(NamedTuple):
    """
    Class to hold product information
    attributes:
        vendor: str
        product: str
        version: str
        location: str
        purl: Optional[str]
    """

    vendor: str
    product: str
    version: str
    location: str
    purl: str | None = None

    def __identity_members(self):
        """The members that will be used for eq and hash implementations.
        We do not include location here since it can take on different values
        depending on where the product info is coming from and we want to be
        able to properly identify products that are actually the same.
        """
        # TODO: what is the meaning of the location field exactly?
        return (self.vendor, self.product, self.version)

    def __eq__(self, other):
        if type(other) is type(self):
            return self.__identity_members() == other.__identity_members()
        else:
            return False

    def __hash__(self):
        return hash(self.__identity_members())


class ScanInfo(NamedTuple):
    """
    Class to hold scan information
    attributes:
        product_info: ProductInfo
        file_path: str
    """

    product_info: ProductInfo
    file_path: str


class VersionInfo(NamedTuple):
    """
    Class to hold version information of a product
    attributes:
        version: str
        version_patterns: list[Pattern[str]]
        ignore: list[Pattern[str]]
    """

    start_including: str
    start_excluding: str
    end_including: str
    end_excluding: str


class CVEData(DefaultDict[str, Union[List[CVE], Set[str]]]):
    """
    A Class representing a dictionary of CVEs and paths
    """

    def __missing__(self, key: str) -> list[CVE] | set[str]:
        """
        Handle missing keys in the dictionary.

        If the key is "cves", a new list is created and assigned to the key.
        If the key is "paths", a new set is created and assigned to the key.
        If the key is neither "cves" nor "paths", NotImplemented is returned.

        Args:
            key (str): The key that was not found.

        Returns:
            list[CVE] | set[str]: The value that was created for the missing key.
        """
        if key == "cves":
            new_list: list[CVE] = []
            self[key] = new_list
        elif key == "paths":
            new_set: set[str] = set()
            self[key] = new_set
        else:
            return NotImplemented
        return self[key]


def regex_find(
    lines: str, version_patterns: list[Pattern[str]], ignore: list[Pattern[str]]
) -> str:
    """Search a set of lines to find a match for the given regex"""
    new_guess = ""

    for pattern in version_patterns:
        match = pattern.search(lines)
        if match:
            new_guess = match.group(1).strip()
            for i in ignore:
                if str(i) in str(new_guess) or str(new_guess) in str(i):
                    new_guess = ""
            break
    if new_guess != "":
        new_guess = new_guess.replace("_", ".")
        return new_guess.replace("-", ".")
    else:
        return "UNKNOWN"


def inpath(binary: str) -> bool:
    """Check to see if something is available in the path.
    Used to check if dependencies are installed before use."""
    if sys.platform == "win32":
        return any(
            list(
                map(
                    lambda dirname: (Path(dirname) / (binary + ".exe")).is_file(),
                    os.environ.get("PATH", "").split(";"),
                )
            )
        )
    return any(
        list(
            map(
                lambda dirname: (Path(dirname) / binary).is_file(),
                os.environ.get("PATH", "").split(":"),
            )
        )
    )


def make_http_requests(attribute, **kwargs):
    """
    Makes an HTTP request and returns the response based on the specified attribute.
    """
    try:
        url = kwargs.pop("url", "")
        timeout = kwargs.pop("timeout", 300)
        response = requests.get(url, timeout=timeout, **kwargs)
        response.raise_for_status()
        if attribute == "text":
            return response.text
        elif attribute == "json":
            return response.json()
        else:
            raise ValueError("Invalid attribute specified")
    except requests.Timeout:
        LOGGER.error(f"Request to {url} timed out.")
    except requests.RequestException as e:
        LOGGER.error(f"An error occurred while fetching {url}: {e}")
    except ValueError as ve:
        LOGGER.error(ve)


def find_product_location(product_name):
    """
    Find the location of a product in the system.
    Returns the location of the product if found, None otherwise.
    """
    for path in sys.path:
        product_location = Path(path) / product_name
        if product_location.exists():
            return str(product_location)
        parts = product_name.split("-")
        for part in parts:
            product_location = Path(path) / part
            if product_location.exists():
                return str(product_location)

    known_installation_directories = [
        "/usr/local/bin",
        "/usr/local/sbin",
        "/usr/bin",
        "/opt",
        "/usr/sbin",
        "/usr/local/lib",
        "/usr/lib",
        "/usr/local/share",
        "/usr/share",
        "/usr/local/include",
        "/usr/include",
    ]

    for directory in known_installation_directories:
        product_location = Path(directory) / product_name
        if product_location.exists():
            return str(product_location)

    return None


def validate_location(location: str) -> bool:
    """
    Validates the location.
    Returns True if the location is valid, False otherwise.
    """
    pattern = r"^(?!https?:\/\/)(?=.*[\\/])(?!.*@)[a-zA-Z0-9_\-\\\/\s]+|NotFound$"
    return bool(re.match(pattern, location))


def decode_purl(purl: str) -> ProductInfo | None:
    """
    Decode a Package URL (purl) in the format: pkg:type/namespace/product@version.

    Args:
    - purl (str): Package URL (purl) string.

    Returns:
    - ProductInfo | None: An instance of ProductInfo containing the vendor, product,
      version, location, and purl, or None if the purl is invalid.
    """
    location = "location/to/product"

    try:
        purl_obj = PackageURL.from_string(purl)
        vendor = purl_obj.namespace
        product = purl_obj.name
        version = purl_obj.version
        if vendor and product and version:
            product_info = ProductInfo(
                vendor=vendor,
                product=product,
                version=version,
                location=location,
                purl=purl,
            )
            return product_info
        else:
            raise ValueError(
                f"Invalid purl: expected format pkg:type/namespace/product@version, got {purl}"
            )

    except Exception as e:
        LOGGER.error(f"Error decoding purl: {e}")
        return None


def decode_bom_ref(ref: str):
    """
    Decodes the BOM reference for each component.

    Args:
    - ref (str): BOM reference string

    Returns:
    - ProductInfo | None: ProductInfo object containing the vendor, product, and version,
      or None if the reference cannot be decoded.

    """
    # urn:cbt:{bom_version}/{vendor}#{product}-{version}
    urn_cbt_ref = re.compile(
        r"urn:cbt:(?P<bom_version>.*?)\/(?P<vendor>.*?)#(?P<product>.*?)-(?P<version>.*)"
    )

    # This URN was added to support CPE's that have dashes in their version field.
    # urn:cbt:{bom_version}/{vendor}#{product}:{version}
    urn_cbt_ext_ref = re.compile(
        r"urn:cbt:(?P<bom_version>.*?)\/(?P<vendor>.*?)#(?P<product>.*?):(?P<version>.*)"
    )

    # urn:cdx:serialNumber/version#bom-ref (https://cyclonedx.org/capabilities/bomlink/)
    urn_cdx = re.compile(
        r"urn:cdx:(?P<bomSerialNumber>.*?)\/(?P<bom_version>.*?)#(?P<bom_ref>.*)"
    )
    urn_cdx_with_purl = re.compile(
        r"urn:cdx:(?P<bomSerialNumber>[^/]+)\/(?P<bom_version>[^#]+)#(?P<purl>pkg:[^\s]+)"
    )
    location = "location/to/product"
    match = (
        urn_cdx_with_purl.match(ref)
        or urn_cbt_ext_ref.match(ref)
        or urn_cbt_ref.match(ref)
        or urn_cdx.match(ref)
    )
    if match:
        urn_dict = match.groupdict()
        if "purl" in urn_dict:  # For urn_cdx_with_purl match
            serialNumber = urn_dict["bomSerialNumber"]
            product_info = decode_purl(urn_dict["purl"])
            if not validate_serialNumber(serialNumber):
                LOGGER.error(
                    f"The BOM link contains an invalid serial number: '{serialNumber}'"
                )
                return product_info
            else:
                return product_info, serialNumber
        elif "bom_ref" in urn_dict:  # For urn_cdx match
            cdx_bom_ref = urn_dict["bom_ref"]
            try:
                product, version = cdx_bom_ref.rsplit("-", 1)
            except ValueError:
                product, version = None, None
            vendor = None
        else:  # For urn_cbt_ext_ref or urn_cbt_ref match
            vendor = urn_dict.get("vendor")
            product = urn_dict.get("product")
            version = urn_dict.get("version")
    else:
        return None

    if product and vendor and version:
        if validate_product_vendor(product, vendor) and validate_version(version):
            return ProductInfo(
                vendor.strip(), product.strip(), version.strip(), location
            )

    return None


def validate_product_vendor(product: str, vendor: str) -> bool:
    """
    Validates if a product name and vendor conform to the CPE 2.3 standard.
    Ensure product name and vendor conform to CPE 2.3 standard.
    See https://csrc.nist.gov/schema/cpe/2.3/cpe-naming_2.3.xsd for naming specification
    """
    cpe_regex = r"\A([A-Za-z0-9\._\-~ %])+\Z"
    return (
        re.search(cpe_regex, product) is not None
        and re.search(cpe_regex, vendor) is not None
    )


def validate_version(version: str) -> bool:
    """
    Validates if a version conform to the CPE 2.3 standard.
    """
    cpe_regex = r"^[a-zA-Z0-9._\-+]+$"
    return re.search(cpe_regex, version) is not None


def validate_serialNumber(serialNumber: str) -> bool:
    """
    Validates the serial number present in sbom
    """
    pattern = r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"
    return re.match(pattern, serialNumber) is not None


class DirWalk:
    """
    for filename in DirWalk('*.c').walk(roots):
        do a thing with the c-files in the roots directories
    """

    def __init__(
        self,
        pattern: str = "*",
        folder_include_pattern: str = "*",
        folder_exclude_pattern: str = ".git",
        file_exclude_pattern: str = "",
        yield_files: bool = True,
        yield_folders: bool = False,
    ) -> None:
        """
        Generator for walking the file system and filtering the results.
        """
        self.pattern = pattern
        self.folder_include_pattern = folder_include_pattern
        self.folder_exclude_pattern = folder_exclude_pattern
        self.file_exclude_pattern = file_exclude_pattern
        self.yield_files = yield_files
        self.yield_folders = yield_folders

    def walk(self, roots: list[str] | None = None) -> Iterator[str]:
        """Walk the directory looking for files matching the pattern"""
        if roots is None:
            roots = []
        for root in roots:
            for dirpath, dirnames, filenames in os.walk(root):
                # Filters
                for filename in filenames.copy():
                    try:
                        if (
                            not self.pattern_match(
                                str(Path(dirpath) / filename), self.pattern
                            )
                            or self.pattern_match(
                                str(Path(dirpath) / filename), self.file_exclude_pattern
                            )
                            or self.pattern_match(
                                str(Path(dirpath) / filename),
                                self.folder_exclude_pattern,
                            )
                            or (Path(dirpath) / filename).is_symlink()
                        ):
                            filenames.remove(filename)
                    except PermissionError:
                        filenames.remove(filename)
                dirnames[:] = [
                    dirname
                    for dirname in dirnames
                    if self.pattern_match(
                        str(Path(dirpath) / dirname), self.folder_include_pattern
                    )
                    and not self.pattern_match(
                        str(Path(dirpath) / dirname), self.folder_exclude_pattern
                    )
                ]
                # Yields
                if self.yield_files:
                    for filename in filenames:
                        yield str((Path(dirpath) / filename).resolve())
                if self.yield_folders:
                    for dirname in dirnames:
                        yield str((Path(dirpath) / dirname).resolve())

    @staticmethod
    def pattern_match(text: str, patterns: str) -> bool:
        """Match filename patterns"""
        if not patterns:
            return False
        for pattern in patterns.split(";"):
            if fnmatch.fnmatch(text, pattern):
                return True
        return False


def decode_cpe23(cpe23) -> list:
    """
    Decode a CPE 2.3 formatted string to extract vendor, product, and version information.

    Args:
    - cpe23 (str): CPE 2.3 formatted string.

    Returns:
    - list[str | None, str | None, str | None]: A tuple containing the vendor, product, and version
      information extracted from the CPE 2.3 string, or None if the information is incomplete.

    """

    # split on `:` only if it's not escaped
    cpe = re.split(r"(?<!\\):", cpe23)
    vendor, product, version = cpe[3], cpe[4], cpe[5]
    # Return available data, convert empty fields to None
    return [vendor or None, product or None, version or None]


def decode_cpe22(cpe22) -> list:
    """
    Decode a CPE 2.2 formatted string to extract vendor, product, and version information.

    Args:
    - cpe22 (str): CPE 2.2 formatted string.

    Returns:
    - Tuple[str | None, str | None, str | None]: A tuple containing the vendor, product, and version
      information extracted from the CPE 2.2 string, or None if the information is incomplete.

    """

    # split on `:` only if it's not escaped
    cpe = re.split(r"(?<!\\):", cpe22)
    vendor, product, version = cpe[2], cpe[3], cpe[4]
    # Return available data, convert empty fields to None
    return [vendor or None, product or None, version or None]


def windows_fixup(filename):
    """Replace colon and backslash in filename to avoid a failure on Windows"""
    return filename.replace(":", "_").replace("\\", "_")
