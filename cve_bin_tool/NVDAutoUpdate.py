# pylint: disable=useless-object-inheritance, too-many-locals, too-many-nested-blocks, too-many-arguments, broad-except
# TODO: we should be able to fix the broad-except, others may require refactoring
""" Import CVE data from NVD """
from __future__ import print_function
import datetime
import json
from os import listdir
from os.path import isfile, join
import os
import sqlite3
import re
import zipfile
import itertools
import hashlib
import shutil
import sys
from collections import namedtuple

# python 2 compatibility
try:
    from urllib2 import urlopen
except ImportError:
    from urllib.request import urlopen
import threading

DLPAGE = "https://nvd.nist.gov/vuln/data-feeds"
DBNAME = "nvd.vulnerabilities.db"
OUTPUTFILE = "%s_output.csv" % (datetime.datetime.now().strftime("%Y%m%d_%H%M%S"))
CREATE_SYNTAX = """CREATE TABLE IF NOT EXISTS nvd_data (
                   CVE_Number TEXT,
                   Vendor_Name TEXT,
                   Product_Name TEXT,
                   Exploitability_Score INTEGER,
                   Impact_Score INTEGER,
                   Severity TEXT,
                   version TEXT,
                   PRIMARY KEY(CVE_Number, Vendor_Name, Product_Name))"""
# TODO Windows
DISK_LOCATION_DEFAULT = os.path.join(os.path.expanduser("~"), ".cache", "cve-bin-tool")
JSON_FEED = "https://nvd.nist.gov/vuln/data-feeds#JSON_FEED"
JSON_ZIP = "https://nvd.nist.gov/feeds/json/cve/1.1/"
JSON_META = "https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-2019.meta"
JSON_FILE = "nvdcve-1.1-2019.json"

CVE = namedtuple("CVE", ["number", "version", "severity"])


def get_cvelist(
    output,
    dbname,
    quiet,
    supplement=True,
    json_feed=JSON_FEED,
    json_zip=JSON_ZIP,
    **kargs
):
    """ Get list of CVEs and add to the database """
    if not os.path.exists(output):
        os.makedirs(output, 0o750)
    conn = init_database(dbname, quiet)

    today = str(datetime.date.today())
    year = str(int(today[:4]))

    threads = []

    # TODO Previous year files will get updated as well.
    r_feed = urlopen(json_feed, **kargs)
    for filename in re.findall(
        r"nvdcve-1.1-[0-9]*\.json\.zip", r_feed.read().decode("utf-8")
    ):
        t = threading.Thread(
            target=download_cves, args=(filename, output, json_zip, kargs, year, quiet)
        )
        t.start()
        threads.append(t)

    for t in threads:
        t.join()

    # extract_data(conn)
    (
        cve_number,
        vendor_name,
        product_name,
        exploitability_score,
        impact_score,
        severity,
        versions,
    ) = extract_data(output)

    if supplement:
        """ Extract supplemental data for packages from various sources """
        find_curl_list(
            cve_number,
            vendor_name,
            product_name,
            exploitability_score,
            impact_score,
            severity,
            versions,
        )

    # print(cve_number[0] + " " + str(exploitability_score[0]) + " " + str(impact_score[0]) + " " + openssl_versions[0])
    store_cve_data(
        conn,
        cve_number,
        vendor_name,
        product_name,
        exploitability_score,
        impact_score,
        severity,
        versions,
    )
    # display_data(conn)
    conn.close()


def download_cves(filename, output, json_zip, kargs, year, quiet):
    r_file = urlopen(json_zip + filename, **kargs)
    filepath = os.path.join(output, filename)
    if year in filename or not os.path.exists(filepath):
        with open(filepath, "wb") as file_handle:
            for chunk in r_file:
                file_handle.write(chunk)
        file_handle.close()
        if not quiet:
            if year in filename:
                print("Updated current year file " + filename)
                # check only 2019 for now (old files not updated)
                if check_cve_zip(2019):
                    if not quiet:
                        print("Verified 2019 zipfile against published sha256 sum")
                else:
                    print(
                        "Error: failed to verify zipfile against published sha256 sum",
                        file=sys.stderr,
                    )
            else:
                print("Creating new file " + filename)
    else:
        if not quiet:
            print("Previous year file: " + filename + " already exists")


def check_cve_zip(year):
    """ Check a given downloaded zip against the meta posted for it.
    Should only be used for recently updated files, or this will fail """

    json_meta = JSON_META.replace("2019", str(year))
    jsonfile_name = JSON_FILE.replace("2019", str(year))
    zipfile_name = os.path.join(
        DISK_LOCATION_DEFAULT, "nvd", "{}.zip".format(jsonfile_name)
    )

    # Meta lines are lastModifiedDate, size, zipSize, gzSize, sha256
    meta = urlopen(json_meta).read().decode("utf-8")
    lines = meta.splitlines()

    # check the zip size
    zipsize = lines[2].split(":")[1]
    if int(zipsize) != os.stat(zipfile_name).st_size:
        return False

    # check the sha256sum
    sha256 = lines[4].split(":")[1].lower()
    with zipfile.ZipFile(zipfile_name, "r") as json_zip:
        with json_zip.open(jsonfile_name) as json_file:
            json_sha256 = hashlib.sha256(json_file.read()).hexdigest()
            return sha256 == json_sha256

    return False


def init_database(dbname, quiet):
    """ Create new database if needed """
    if not quiet and (not os.path.isfile(dbname)):
        print("Database file does not exist. Initializing it")
    conn = sqlite3.connect(dbname)
    db_cursor = conn.cursor()
    db_cursor.execute(CREATE_SYNTAX)
    db_cursor.execute(
        """CREATE INDEX IF NOT EXISTS vendors ON nvd_data(CVE_Number, Vendor_Name, Product_Name)"""
    )
    return conn


def find_curl_list(
    cve_number,
    vendor_name,
    product_name,
    exploitability_score,
    impact_score,
    severity,
    versions,
):
    """ Extract curl data """
    # import urllib.request

    cve_pattern = re.compile('name=(CVE-[^"]*)')
    nextver_pattern = re.compile(r"the subsequent release: ([\d.]+)")

    # Start with version 6.0 since that's currently first
    version = "6.0"

    cve_dict = {}
    while version:
        url = "https://curl.haxx.se/docs/vuln-" + version + ".html"
        # print("Getting from " + url)

        # request = urllib.request.Request(url)
        # response = urllib.request.urlopen(request)
        response = urlopen(url)
        html = response.read()
        text = html.decode("utf-8")

        cves = re.findall(cve_pattern, text)
        # print("    has_curl_cves[\"" + version + "\"] = ", end = "")
        # print(cves)

        for number in cves:
            if number in cve_dict:
                cve_dict[number] += ", " + version
            else:
                cve_dict[number] = version
        nextversion = re.findall(nextver_pattern, text)
        if nextversion:
            version = nextversion[0]
        else:
            version = None
    for number, version in cve_dict.items():
        # print (number, version)
        cve_number.append(number)
        versions.append(version)
        vendor_name.append("haxx")
        product_name.append("curl")
        exploitability_score.append("")
        impact_score.append("")
        severity.append("")


def extract_data(nvddir):

    """ Extract NVD data """
    files = [f for f in listdir(nvddir) if isfile(join(nvddir, f))]
    files.sort()
    cve_number = []
    vendor_name = []
    exploitability_score = []
    impact_score = []
    versions = []
    severity = []
    product_name = []
    for file in files:
        try:
            archive = zipfile.ZipFile(join(nvddir, file), "r")
            jsonfile = archive.open(archive.namelist()[0])
            cve_dict = json.loads(jsonfile.read().decode("utf-8"))

            # Go through all CVE_Items (every CVE in the json)
            for cve_item in cve_dict["CVE_Items"]:
                CVE = dict()
                CVE["ID"] = cve_item["cve"]["CVE_data_meta"]["ID"]

                # get score
                if "baseMetricV3" in cve_item["impact"]:
                    CVE["severity"] = cve_item["impact"]["baseMetricV3"]["cvssV3"][
                        "baseSeverity"
                    ]
                    CVE["exploitability"] = cve_item["impact"]["baseMetricV3"][
                        "exploitabilityScore"
                    ]
                    CVE["impact"] = cve_item["impact"]["baseMetricV3"]["impactScore"]
                elif "baseMetricV2" in cve_item["impact"]:
                    CVE["severity"] = cve_item["impact"]["baseMetricV2"]["severity"]
                    CVE["exploitability"] = cve_item["impact"]["baseMetricV2"][
                        "exploitabilityScore"
                    ]
                    CVE["impact"] = cve_item["impact"]["baseMetricV2"]["impactScore"]
                else:
                    CVE["severity"] = "unknown"
                    CVE["exploitability"] = "unknown"
                    CVE["impact"] = "unknown"

                # get all the affected products
                affects_list = []
                if "configurations" in cve_item:
                    for node in cve_item["configurations"]["nodes"]:
                        affects_list.extend(parse_node(node))
                        if "children" in node:
                            for child in node["children"]:
                                affects_list.extend(parse_node(child))

                vendorproduct_list = sorted(
                    [[row["vendor"], row["product"]] for row in affects_list]
                )
                # FIXME: dedupe here (currently trusting the db to do it)

                # make a versions list for each vendor/product pair, add whole shebang to db
                for vend, prod in vendorproduct_list:
                    ver_list = [
                        row["version"]
                        for row in affects_list
                        if row["vendor"] is vend and row["product"] is prod
                    ]

                    cve_number.append(CVE["ID"])
                    severity.append(CVE["severity"])
                    exploitability_score.append(CVE["exploitability"])
                    impact_score.append(CVE["impact"])
                    product_name.append(prod)
                    vendor_name.append(vend)
                    versions.append(", ".join(ver_list))

            jsonfile.close()
        except Exception as exception:
            print("Exception in extract_data: " + str(exception))

    return (
        cve_number,
        vendor_name,
        product_name,
        exploitability_score,
        impact_score,
        severity,
        versions,
    )


def parse_node(node):
    affects_list = []
    if "cpe_match" in node:
        for cpe_match in node["cpe_match"]:
            cpe_split = cpe_match["cpe23Uri"].split(":")
            affects = dict()
            affects["vendor"] = cpe_split[3]
            affects["product"] = cpe_split[4]
            affects["version"] = cpe_split[5]
            if affects["version"] is "*":
                # Not Dealing with ranges yet, but let's at least get start/end in
                if "versionStartIncluding" in cpe_match:
                    affects["version"] = cpe_match["versionStartIncluding"]
                    affects_list.append(affects)

                if "versionEndIncluding" in cpe_match:
                    affects["version"] = cpe_match["versionEndIncluding"]
                    affects_list.append(affects)
            else:
                affects_list.append(affects)
    return affects_list


def store_cve_data(
    conn,
    cve_number,
    vendor_name,
    product_name,
    exploitability_score,
    impact_score,
    severity,
    versions,
):
    """ Store NVD data in database """
    cur = conn.cursor()
    for i, dummy_item in enumerate(cve_number):
        try:
            cur.execute(
                """INSERT OR REPLACE INTO nvd_data(CVE_Number,Vendor_Name,Product_Name,Exploitability_Score,Impact_Score,Severity,version) VALUES(?,?,?,?,?,?,?)""",
                (
                    cve_number[i],
                    vendor_name[i],
                    product_name[i],
                    exploitability_score[i],
                    impact_score[i],
                    severity[i],
                    versions[i],
                ),
            )
        except Exception as exception:
            print("Exception in store_cve_data: " + str(exception))
    lastrowid = cur.lastrowid
    conn.commit()
    return lastrowid


def display_data(conn):
    """ Display some data (formerly used for debugging) """
    cur = conn.cursor()
    cur.execute(
        '''SELECT * FROM nvd_data where CVE_Number = "CVE-2018-9999"'''
    )  # No xml2, xerces, libnss
    rows = cur.fetchall()
    for row in rows:
        print(row)


def get_cvelist_if_stale(nvddir, dbname, quiet):
    """ If the local copy of the cvelist is more than a day old, download a new one.
    This allows some caching so you don't have to wait for the full download with every
    single execution. """
    this_year = datetime.datetime.today().year
    latest_zipfile = os.path.join(nvddir, "nvdcve-1.1-" + str(this_year) + ".json.zip")

    if not os.path.isfile(latest_zipfile) or (
        datetime.datetime.today()
        - datetime.datetime.fromtimestamp(os.path.getmtime(latest_zipfile))
    ) > datetime.timedelta(hours=24):
        if not quiet:
            print("Updating CVE data. This will take a few minutes.")
        get_cvelist(nvddir, dbname, quiet)

    if not os.path.isfile(dbname):
        conn = init_database(dbname, quiet)
        (
            cve_number,
            vendor_name,
            product_name,
            exploitability_score,
            impact_score,
            severity,
            versions,
        ) = extract_data(nvddir)
        store_cve_data(
            conn,
            cve_number,
            vendor_name,
            product_name,
            exploitability_score,
            impact_score,
            severity,
            versions,
        )
        conn.close()

    elif not quiet:
        print(
            "Last Update: "
            + datetime.date.fromtimestamp(os.path.getmtime(dbname)).isoformat()
        )
        print("Local database has been updated in the past 24h.")
        print('New data not downloaded.  Use "-u now" to force an update')


class NVDSQLite(object):
    """ Methods for NVD stored in sqlite """

    def __init__(self, disk_location=DISK_LOCATION_DEFAULT, quiet=False):
        """ Set location on disk where NVD data cache will reside.
        Connect to SQLite database"""
        self.disk_location = disk_location
        self.conn = None
        self.quiet = quiet

    @property
    def dbname(self):
        """ SQLite datebase file where imported NVD data is stored."""
        return os.path.join(self.disk_location, DBNAME)

    @property
    def nvddir(self):
        """ Directory where NVD zipfiles are stored."""
        return os.path.join(self.disk_location, "nvd")

    def open(self):
        """ Opens connection to sqlite database."""
        self.conn = sqlite3.connect(self.dbname, check_same_thread=False)

    def close(self):
        """ Closes connection to sqlite database."""
        self.conn.close()
        self.conn = None

    def __enter__(self):
        """ Opens connection to sqlite database."""
        self.open()

    def __exit__(self, exc_type, exc, exc_tb):
        """ Closes connection to sqlite database."""
        self.close()

    def get_cves(self, *vendor_product_pairs):
        """ Get CVEs against a specific version of a package.

        Example:
            nvd.get_cves(('haxx', 'curl', '7.34.0'))
            nvd.get_cves(('haxx', 'curl', '7.34.0'), ('rubygems', 'curl', '7.34.0'))
        """
        cur = self.conn.cursor()
        query = (
            "SELECT CVE_Number, version, Severity FROM nvd_data WHERE "
            + " OR ".join(
                itertools.chain(
                    [
                        "(Vendor_Name=? AND Product_Name=? AND (version like ? OR version = '-'))"
                    ]
                    * len(vendor_product_pairs)
                )
            )
        )
        if len(vendor_product_pairs) == 1:
            print(vendor_product_pairs[0])
            cur.execute(query, vendor_product_pairs[0])
        else:
            cur.execute(query, tuple(itertools.chain(*vendor_product_pairs)))
        return list(map(CVE._make, cur.fetchall()))

    def get_cvelist_if_stale(self):
        """ Update CVEs data from NVD if stale."""
        get_cvelist_if_stale(self.nvddir, self.dbname, self.quiet)

    @classmethod
    def clear_cached_data(cls):
        if os.path.exists(DISK_LOCATION_DEFAULT):
            shutil.rmtree(DISK_LOCATION_DEFAULT)
