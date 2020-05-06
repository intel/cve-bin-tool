"""
Retrieval access and caching of NIST CVE database
"""
import os
import re
import datetime
import gzip
import json
import glob
import shutil
import sqlite3
import hashlib
import logging
import tempfile
import functools
import traceback
import contextlib
import multiprocessing

try:
    import urllib.request as request
except:
    import urllib2 as request

from collections import namedtuple
from string import ascii_lowercase
from cve_bin_tool.log import LOGGER
from pkg_resources import parse_version

logging.basicConfig(level=logging.DEBUG)

# database defaults
DISK_LOCATION_DEFAULT = os.path.join(os.path.expanduser("~"), ".cache", "cve-bin-tool")
DBNAME = "cve.db"
OLD_CACHE_DIR = os.path.join(os.path.expanduser("~"), ".cache", "cvedb")


class EmptyCache(Exception):
    """
    Raised when NVD is opened when verify=False and there are no files in the
    cache.
    """


class CVEDataForYearNotInCache(Exception):
    """
    Raised when the CVE data for a year is not present in the cache.
    """


class AttemptedToWriteOutsideCachedir(Exception):
    """
    Raised if we attempted to write to a file that would have been outside the
    cachedir.
    """


class SHAMismatch(Exception):
    """
    Raised if the sha of a file in the cache was not what it should be.
    """


def log_traceback(func, *args, **kwargs):
    """
    Multiprocessing won't print tracebacks, so log them
    """
    logger = logging.getLogger(__name__ + "." + func.__name__)
    try:
        return func(*args, logger=logger, **kwargs)
    except:
        logger.error(traceback.format_exc().strip())
        raise


def getmeta(metaurl, logger=LOGGER):
    with contextlib.closing(request.urlopen(metaurl)) as response:
        return (
            metaurl.replace(".meta", ".json.gz"),
            dict(
                [
                    line.split(":", 1)
                    for line in (response.read().decode()).split("\r\n")
                    if ":" in line
                ]
            ),
        )


def cache_update(cachedir, url, sha, chunk_size=16 * 1024, logger=LOGGER):
    """
    Update the cache for a single year of NVD data.
    """
    filename = url.split("/")[-1]
    # Ensure we only write to files within the cachedir
    filepath = os.path.abspath(os.path.join(cachedir, filename))
    if not filepath.startswith(os.path.abspath(cachedir)):
        raise AttemptedToWriteOutsideCachedir(filepath)
    # Validate the contents of the cached file
    if os.path.isfile(filepath):
        # Validate the sha and write out
        sha = sha.upper()
        calculate = hashlib.sha256()
        with gzip.open(filepath, "rb") as handle:
            chunk = handle.read(chunk_size)
            while chunk:
                calculate.update(chunk)
                chunk = handle.read(chunk_size)
        # Validate the sha and exit if it is correct, otherwise update
        gotsha = calculate.hexdigest().upper()
        if gotsha != sha:
            os.unlink(filepath)
            logger.warning(f"SHA mismatch for {filename} (have: {gotsha}, want: {sha})")
        else:
            logger.debug(f"Correct SHA for {filename}")
            return
    logger.info(f"Updating CVE cache for {filename}")
    with tempfile.TemporaryFile(prefix="cvedb-") as temp_file:
        with contextlib.closing(request.urlopen(url)) as response:
            # Write to tempfile (gzip doesnt support reading from urlopen on
            # Python 2)
            shutil.copyfileobj(response, temp_file)
        # Replace the file with the tempfile
        temp_file.seek(0)
        with gzip.GzipFile(fileobj=temp_file, mode="rb") as jsondata_fileobj:
            # Validate the sha
            sha = sha.upper()
            calculate = hashlib.sha256()
            # Copy the contents while updating the sha
            with gzip.open(filepath, "wb") as filepath_handle:
                chunk = jsondata_fileobj.read(chunk_size)
                while chunk:
                    calculate.update(chunk)
                    filepath_handle.write(chunk)
                    chunk = jsondata_fileobj.read(chunk_size)
            # Raise error if there was an issue with the sha
            gotsha = calculate.hexdigest().upper()
            if gotsha != sha:
                # Remove the file if there was an issue
                os.unlink(filepath)
                raise SHAMismatch(f"{url} (have: {gotsha}, want: {sha})")


class CVEDB(object):
    """
    Downloads NVD data in json form and stores it on disk in a cache.
    """

    CACHEDIR = DISK_LOCATION_DEFAULT
    FEED = "https://nvd.nist.gov/vuln/data-feeds"
    LOGGER = LOGGER.getChild("CVEDB")
    NVDCVE_FILENAME_TEMPLATE = "nvdcve-1.1-{}.json.gz"
    META_REGEX = re.compile(r"https:\/\/.*\/json\/.*-[0-9]*\.[0-9]*-[0-9]*\.meta")
    RANGE_UNSET = ""

    def __init__(self, verify=True, feed=None, cachedir=None):
        self.verify = verify
        self.feed = feed if feed is not None else self.FEED
        self.cachedir = cachedir if cachedir is not None else self.CACHEDIR
        # Will be true if refresh was successful
        self.was_updated = False

        # set up the db if needed
        self.disk_location = DISK_LOCATION_DEFAULT
        self.dbname = os.path.join(self.disk_location, DBNAME)
        self.connection = None

    def nist_scrape(self, feed):
        with contextlib.closing(request.urlopen(feed)) as response:
            page = response.read().decode()
            jsonmetalinks = self.META_REGEX.findall(page)
            pool = multiprocessing.Pool()
            try:
                metadata = dict(
                    pool.map(
                        functools.partial(log_traceback, getmeta), tuple(jsonmetalinks)
                    )
                )
                pool.close()
                return metadata
            except:
                pool.terminate()
                raise
            finally:
                pool.join()

    def init_database(self):
        """ Initialize db tables used for storing cve/version data """
        conn = sqlite3.connect(self.dbname)
        db_cursor = conn.cursor()
        cve_data_create = """CREATE TABLE IF NOT EXISTS cve_severity (
        cve_number TEXT,
        severity TEXT,
        score INTEGER,
        cvss_version INTEGER,
        PRIMARY KEY(cve_number)
        )
        """
        db_cursor.execute(cve_data_create)

        version_range_create = """ CREATE TABLE IF NOT EXISTS cve_range (
        cve_number TEXT,
        vendor TEXT,
        product TEXT,
        version TEXT,
        versionStartIncluding TEXT,
        versionStartExcluding TEXT,
        versionEndIncluding TEXT,
        versionEndExcluding TEXT
        )
        """
        db_cursor.execute(version_range_create)

        index_range = """CREATE INDEX IF NOT EXISTS product_index ON cve_range (cve_number, vendor, product)"""
        db_cursor.execute(index_range)
        conn.commit()
        return conn

    def open(self):
        """ Opens connection to sqlite database."""
        self.connection = sqlite3.connect(self.dbname, check_same_thread=False)

    def close(self):
        """ Closes connection to sqlite database."""
        self.connection.close()
        self.connection = None

    def __enter__(self):
        """ Opens connection to sqlite database."""
        self.open()

    def __exit__(self, exc_type, exc, exc_tb):
        """ Closes connection to sqlite database."""
        self.close()

    def get_cvelist_if_stale(self):
        """ Update if the local db is more than one day old.
        This avoids the full slow update with every execution.
        """
        if not os.path.isfile(self.dbname) or (
            datetime.datetime.today()
            - datetime.datetime.fromtimestamp(os.path.getmtime(self.dbname))
        ) > datetime.timedelta(hours=24):
            self.refresh_cache_and_update_db()
        else:
            self.LOGGER.info(
                "Using cached CVE data (<24h old). Use -u now to update immediately."
            )

    def refresh_cache_and_update_db(self):
        self.LOGGER.info("Updating CVE data. This will take a few minutes.")
        # refresh the nvd cache
        self.refresh()
        # if the database isn't open, open it
        if self.connection is None:
            self.connection = self.init_database()
        self.populate_db()

    def get_cves(self, vendor, product, version):
        """ Get CVEs against a specific version of a package.

        Example:
            nvd.get_cves('haxx', 'curl', '7.34.0')
        """
        if self.connection is None:
            self.open()
        cursor = self.connection.cursor()

        # Check for anything directly marked
        query = """SELECT CVE_number FROM cve_range WHERE
        vendor=? AND product=? AND version=?"""
        cursor.execute(query, [vendor, product, version])
        cve_list = list(map(lambda x: x[0], cursor.fetchall()))

        # Check for any ranges
        query = """SELECT CVE_number, versionStartIncluding, versionStartExcluding, versionEndIncluding, versionEndExcluding FROM cve_range WHERE
        vendor=? AND product=? AND version=?"""
        cursor.execute(query, [vendor, product, "*"])
        for cve_range in cursor:
            (
                cve_number,
                versionStartIncluding,
                versionStartExcluding,
                versionEndIncluding,
                versionEndExcluding,
            ) = cve_range

            # pep-440 doesn't include versions of the type 1.1.0g used by openssl
            # so if this is openssl, convert the last letter to a .number
            if product == "openssl":
                # if last character is a letter, convert it to .number
                version = self.openssl_convert(version)
                versionStartIncluding = self.openssl_convert(versionStartIncluding)
                versionStartExcluding = self.openssl_convert(versionStartExcluding)
                versionEndIncluding = self.openssl_convert(versionEndIncluding)
                versionEndExcluding = self.openssl_convert(versionEndExcluding)

            parsed_version = parse_version(version)

            # check the start range
            passes_start = False
            if (
                versionStartIncluding is not self.RANGE_UNSET
                and parsed_version >= parse_version(versionStartIncluding)
            ):
                passes_start = True
            if (
                versionStartExcluding is not self.RANGE_UNSET
                and parsed_version > parse_version(versionStartExcluding)
            ):
                passes_start = True

            if (
                versionStartIncluding is self.RANGE_UNSET
                and versionStartExcluding is self.RANGE_UNSET
            ):
                # then there is no start range so just say true
                passes_start = True

            # check the end range
            passes_end = False
            if (
                versionEndIncluding is not self.RANGE_UNSET
                and parsed_version <= parse_version(versionEndIncluding)
            ):
                passes_end = True

            if (
                versionEndExcluding is not self.RANGE_UNSET
                and parsed_version < parse_version(versionEndExcluding)
            ):
                passes_end = True
            if (
                versionEndIncluding is self.RANGE_UNSET
                and versionEndExcluding is self.RANGE_UNSET
            ):
                # then there is no end range so it passes
                passes_end = True
            # if it fits into both ends of the range, add the cve number
            if passes_start and passes_end:
                cve_list.append(cve_number)

        # Go through and get all the severities
        if cve_list:
            query = f'SELECT CVE_number, severity from cve_severity where CVE_number IN ({",".join(["?"]*len(cve_list))}) ORDER BY CVE_number ASC'
            cursor.execute(query, cve_list)
            # Everything expects a data structure of cve[number] = severity so you can search through keys
            # and do other easy manipulations
            return dict(cursor)

        return cve_list

    def openssl_convert(self, version):
        """ pkg_resources follows pep-440 which doesn't expect openssl style 1.1.0g version numbering
        So to fake it, if the last character is a letter, replace it with .number before comparing """
        if len(version) < 1:
            return version

        lastchar = version[len(version) - 1]
        letters = dict(zip(ascii_lowercase, range(26)))

        if lastchar in letters:
            version = f"{version[0 : len(version) - 1]}.{letters[lastchar]}"
        return version

    def populate_db(self):
        """ Function that populates the database from the JSON.

        WARNING: After some inspection of the data, we are assuming that start/end ranges are kept together
        in single nodes.  This isn't *required* by the json so may not be true everywhere.  If that's the case,
        we'll need a better parser to match those together.
        """
        if self.connection is None:
            self.connection = self.open()

        cursor = self.connection.cursor()

        # Do only years with updates?
        for year in self.years():
            cve_data = self.year(year)
            self.LOGGER.debug(
                f'Time = {datetime.datetime.today().strftime("%H:%M:%S")}'
            )
            for cve_item in cve_data["CVE_Items"]:
                # the information we want:
                # CVE ID, Severity, Score ->
                # affected {Vendor(s), Product(s), Version(s)}
                CVE = dict()
                CVE["ID"] = cve_item["cve"]["CVE_data_meta"]["ID"]

                # Get CVSSv3 or CVSSv2 score for output.
                # Details are left as an exercise to the user.
                CVE["severity"] = "unknown"
                CVE["score"] = "unknown"
                CVE["CVSS_version"] = "unknown"
                if "baseMetricV3" in cve_item["impact"]:
                    CVE["severity"] = cve_item["impact"]["baseMetricV3"]["cvssV3"][
                        "baseSeverity"
                    ]
                    CVE["score"] = cve_item["impact"]["baseMetricV3"]["cvssV3"][
                        "baseScore"
                    ]
                    CVE["CVSS_version"] = 3
                elif "baseMetricV2" in cve_item["impact"]:
                    CVE["severity"] = cve_item["impact"]["baseMetricV2"]["severity"]
                    CVE["score"] = cve_item["impact"]["baseMetricV2"]["cvssV2"][
                        "baseScore"
                    ]
                    CVE["CVSS_version"] = 2

                # self.LOGGER.debug(
                #    "Severity: {} ({}) v{}".format(
                #        CVE["severity"], CVE["score"], CVE["CVSS_version"]
                #    )
                # )

                q = "INSERT or REPLACE INTO cve_severity(CVE_number, severity, score, cvss_version) \
                VALUES (?, ?, ?, ?)"
                cursor.execute(
                    q, [CVE["ID"], CVE["severity"], CVE["score"], CVE["CVSS_version"]]
                )

                # Delete any old range entries for this CVE_number
                q_del = "DELETE from cve_range where CVE_number=?"
                cursor.execute(q_del, (CVE["ID"],))

                # walk the nodes with version data
                # return list of versions
                affects_list = []
                if "configurations" in cve_item:
                    for node in cve_item["configurations"]["nodes"]:
                        # self.LOGGER.debug("NODE: {}".format(node))
                        affects_list.extend(self.parse_node(node))
                        if "children" in node:
                            for child in node["children"]:
                                affects_list.extend(self.parse_node(child))
                # self.LOGGER.debug("Affects: {}".format(affects_list))

                q = "INSERT or REPLACE INTO cve_range(cve_number, vendor, product, version, versionStartIncluding, versionStartExcluding, versionEndIncluding, versionEndExcluding) \
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)"
                for affected in affects_list:
                    cursor.execute(
                        q,
                        [
                            CVE["ID"],
                            affected["vendor"],
                            affected["product"],
                            affected["version"],
                            affected["versionStartIncluding"],
                            affected["versionStartExcluding"],
                            affected["versionEndIncluding"],
                            affected["versionEndExcluding"],
                        ],
                    )
            self.connection.commit()

        # supplemental data gets added here
        self.supplement_curl()

    def parse_node(self, node):
        affects_list = []
        if "cpe_match" in node:
            for cpe_match in node["cpe_match"]:
                # self.LOGGER.debug(cpe_match["cpe23Uri"])
                cpe_split = cpe_match["cpe23Uri"].split(":")
                affects = dict()
                affects["vendor"] = cpe_split[3]
                affects["product"] = cpe_split[4]
                affects["version"] = cpe_split[5]

                # self.LOGGER.debug(
                #    "Vendor: {} Product: {} Version: {}".format(
                #        affects["vendor"], affects["product"], affects["version"]
                #    )
                # )
                # if we have a range (e.g. version is *) fill it out, and put blanks where needed
                range_fields = [
                    "versionStartIncluding",
                    "versionStartExcluding",
                    "versionEndIncluding",
                    "versionEndExcluding",
                ]
                for field in range_fields:
                    if field in cpe_match:
                        affects[field] = cpe_match[field]
                    else:
                        affects[field] = self.RANGE_UNSET

                affects_list.append(affects)
        return affects_list

    def refresh(self):
        if not os.path.isdir(self.cachedir):
            os.makedirs(self.cachedir)
        update = self.nist_scrape(self.feed)
        pool = multiprocessing.Pool()
        try:
            for result in [
                pool.apply_async(
                    functools.partial(log_traceback, cache_update),
                    (self.cachedir, url, meta["sha256"]),
                )
                for url, meta in update.items()
            ]:
                result.get()
            pool.close()
            self.was_updated = True
        except:
            pool.terminate()
            raise
        finally:
            pool.join()

    def supplement_curl(self):
        """
        Get additional CVE data directly from the curl website amd add it to the cvedb
        """
        if not self.connection:
            self.open()

        cursor = self.connection.cursor()

        cve_pattern = re.compile('name=(CVE-[^"]*)')
        nextver_pattern = re.compile(r"the subsequent release: ([\d.]+)")

        # 6.0 is the oldest available so start there
        version = "6.0"
        cve_dict = {}
        while version:
            # get data from curl.haxx.se and parse
            url = f"https://curl.haxx.se/docs/vuln-{version}.html"
            response = request.urlopen(url)
            html = response.read()
            text = html.decode("utf-8")

            # insert each CVE separately into the range table
            # note: no deduplication against existing data
            cves = re.findall(cve_pattern, text)
            query = "INSERT INTO cve_range (CVE_Number, vendor, product, version) VALUES (?, ?, ?, ?)"
            for cve_number in cves:
                cursor.execute(query, [cve_number, "haxx", "curl", version])
            # check for next page of vulnerabilities
            nextversion = re.findall(nextver_pattern, text)
            if nextversion:
                version = nextversion[0]
            else:
                version = None
        self.connection.commit()

    def year(self, year):
        """
        Return the dict of CVE data for the given year.
        """
        filename = os.path.join(
            self.cachedir, self.NVDCVE_FILENAME_TEMPLATE.format(year)
        )
        # Check if file exists
        if not os.path.isfile(filename):
            raise CVEDataForYearNotInCache(year)
        # Open the file and load the JSON data, log the number of CVEs loaded
        with gzip.open(filename, "rb") as fileobj:
            cves_for_year = json.load(fileobj)
            self.LOGGER.debug(
                f'Year {year} has {len(cves_for_year["CVE_Items"])} CVEs in dataset'
            )
            return cves_for_year

    def years(self):
        """
        Return the years we have NVD data for.
        """
        return sorted(
            [
                int(filename.split(".")[-3].split("-")[-1])
                for filename in glob.glob(
                    os.path.join(self.cachedir, "nvdcve-1.1-*.json.gz")
                )
            ]
        )

    def __enter__(self):
        if not self.verify:
            self.LOGGER.error("Not verifying CVE DB cache")
            if not self.years():
                raise EmptyCache(self.cachedir)
        self.LOGGER.debug(f"Years present: {self.years()}")
        return self

    def __exit__(self, _exc_type, _exc_value, _traceback):
        pass

    def clear_cached_data(self):
        if os.path.exists(self.cachedir):
            self.LOGGER.warning(f"Deleting cachedir {self.cachedir}")
            shutil.rmtree(self.cachedir)
        # Remove files associated with pre-1.0 development tree
        if os.path.exists(OLD_CACHE_DIR):
            self.LOGGER.warning(f"Deleting old cachedir {OLD_CACHE_DIR}")
            shutil.rmtree(OLD_CACHE_DIR)


def refresh():
    with CVEDB():
        pass


if __name__ == "__main__":
    LOGGER.debug("Experimenting...")
    cvedb = CVEDB(DISK_LOCATION_DEFAULT)
    # cvedb.refresh()
    # print(cvedb.years())
    # connection = cvedb.init_database()
    # cvedb.populate_db(connection)
    # cvedb.supplement_curl()
    LOGGER.setLevel(logging.INFO)
    LOGGER.info("Getting cves for curl 7.34.0")
    LOGGER.info(cvedb.get_cves("haxx", "curl", "7.34.0"))
