import sys
import abc
import datetime
import json
from os import listdir
from os.path import isfile, join
import os
import sqlite3
import re
import zipfile
import itertools
from collections import namedtuple
if sys.version_info.major == 3:
    from urllib.request import urlopen
else:
    from urllib2 import urlopen

DLPAGE = "https://nvd.nist.gov/download.cfm"
DBNAME = "nvd.vulnerabilities.db"
OUTPUTFILE = "%s_output.csv" % (datetime.datetime.now().strftime("%Y%m%d_%H%M%S"))
CREATE_SYNTAX = '''CREATE TABLE IF NOT EXISTS nvd_data (
                   CVE_Number TEXT,
                   Vendor_Name TEXT,
                   Product_Name TEXT,
                   Exploitability_Score INTEGER,
                   Impact_Score INTEGER,
                   Severity TEXT,
                   version TEXT,
                   PRIMARY KEY(CVE_Number, Vendor_Name, Product_Name))'''
# TODO Windows
DISK_LOCATION_DEFAULT = os.path.join(os.path.expanduser('~'), '.cache',
        'cve-bin-tool')
JSON_FEED = 'https://nvd.nist.gov/vuln/data-feeds#JSON_FEED'
JSON_ZIP = 'https://static.nvd.nist.gov/feeds/json/cve/1.0/'

CVE = namedtuple('CVE', ['number', 'version', 'severity'])

def get_cvelist(output, dbname, json_feed=JSON_FEED, json_zip=JSON_ZIP, **kargs):
    if not os.path.exists(output):
        os.makedirs(output)
    conn = init_database(dbname)

    today = str(datetime.date.today())
    year = str(int(today[:4]))

    # TODO Previous year files will get updated as well.
    r = urlopen(json_feed, **kargs)
    for filename in re.findall("nvdcve-1.0-[0-9]*\.json\.zip", r.read().decode('utf-8')):
        r_file = urlopen(json_zip + filename, **kargs)
        filepath = os.path.join(output, filename)
        if year in filename or not os.path.exists(filepath):
            with open(filepath, 'wb') as f:
                for chunk in r_file:
                    f.write(chunk)
            f.close()
            if year in filename:
                print("Updated current year file "+ filename)
            else:
                print("Creating new file "+ filename)
        else:
            print("Previous year file: " + filename+" already exists")

    #extract_data(conn)
    cve_number, vendor_name, product_name, exploitability_score, impact_score, severity, versions = extract_data(output)
    #print(cve_number[0] + " " + str(exploitability_score[0]) + " " + str(impact_score[0]) + " " + openssl_versions[0])
    store_cve_data(conn, cve_number, vendor_name, product_name, exploitability_score, impact_score, severity, versions)
    display_data(conn)
    conn.close()


def init_database(dbname):
    if not os.path.isfile(dbname):
        print("Database file does not exist. Initializing it")
    conn = sqlite3.connect(dbname)
    c = conn.cursor()
    c.execute(CREATE_SYNTAX)
    c.execute('''CREATE INDEX IF NOT EXISTS vendors ON nvd_data(CVE_Number, Vendor_Name, Product_Name)''')
    return conn


def extract_data(nvddir):
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
            archive = zipfile.ZipFile(join(nvddir, file), 'r')
            jsonfile = archive.open(archive.namelist()[0])
            cve_dict = json.loads(jsonfile.read().decode("utf-8"))
            # print(len(cve_dict["CVE_Items"]))
            for i, item in enumerate(cve_dict["CVE_Items"]):
                #print(cve_dict["CVE_Items"][i]["cve"]["CVE_data_meta"]["ID"])

                if cve_dict["CVE_Items"][i]["cve"]["affects"]["vendor"]["vendor_data"]:
                    for x, ven in enumerate(cve_dict["CVE_Items"][i]["cve"]["affects"]["vendor"]["vendor_data"]):
                        ver = ''
                        k = 0
                        cve_number.append(cve_dict["CVE_Items"][i]["cve"]["CVE_data_meta"]["ID"])
                        vendor_name.append(cve_dict["CVE_Items"][i]["cve"]["affects"]["vendor"]["vendor_data"][x]["vendor_name"])
                        product_name.append(cve_dict["CVE_Items"][i]["cve"]["affects"]["vendor"]["vendor_data"][x]["product"]["product_data"][0]["product_name"])
                        for j, item in enumerate(cve_dict["CVE_Items"][i]["cve"]["affects"]["vendor"]["vendor_data"][x]["product"]["product_data"][0]["version"]["version_data"]):
                            if k == 0:
                                ver = cve_dict["CVE_Items"][i]["cve"]["affects"]["vendor"]["vendor_data"][x]["product"]["product_data"][0]["version"]["version_data"][j]["version_value"]
                                k = k + 1
                            else:
                                ver = ver + ', ' + cve_dict["CVE_Items"][i]["cve"]["affects"]["vendor"]["vendor_data"][x]["product"]["product_data"][0]["version"]["version_data"][j]["version_value"]
                        versions.append(ver)

                        if 'baseMetricV3' not in cve_dict["CVE_Items"][i]["impact"]:
                            exploitability_score.append(cve_dict["CVE_Items"][i]["impact"]["baseMetricV2"]["exploitabilityScore"])
                            impact_score.append(cve_dict["CVE_Items"][i]["impact"]["baseMetricV2"]["impactScore"])
                            severity.append(cve_dict["CVE_Items"][i]["impact"]["baseMetricV2"]["severity"])
                        else:
                            exploitability_score.append(cve_dict["CVE_Items"][i]["impact"]["baseMetricV3"]["exploitabilityScore"])
                            impact_score.append(cve_dict["CVE_Items"][i]["impact"]["baseMetricV3"]["impactScore"])
                            severity.append(cve_dict["CVE_Items"][i]["impact"]["baseMetricV3"]["cvssV3"]["baseSeverity"])

            jsonfile.close()
        except Exception as e:
            print("Exception in extract_data: " + str(e))
    return cve_number, vendor_name, product_name, exploitability_score, impact_score, severity, versions


def store_cve_data(conn, cve_number, vendor_name, product_name, exploitability_score, impact_score, severity, versions):
    cur = conn.cursor()
    for i, item in enumerate(cve_number):
        try:
            cur.execute('''INSERT OR REPLACE INTO nvd_data(CVE_Number,Vendor_Name,Product_Name,Exploitability_Score,Impact_Score,Severity,version) VALUES(?,?,?,?,?,?,?)''', (cve_number[i], vendor_name[i], product_name[i], exploitability_score[i], impact_score[i], severity[i], versions[i]))
        except Exception as e:
            print("Exception in store_cve_data: " + str(e))
    pk = cur.lastrowid
    conn.commit()
    return pk


def display_data(conn):
    cur = conn.cursor()
    cur.execute('''SELECT * FROM nvd_data where CVE_Number = "CVE-2018-9999"''') #No xml2, xerces, libnss
    rows = cur.fetchall()
    for row in rows:
        print(row)

def get_cvelist_if_stale(nvddir, dbname):
    this_year = datetime.datetime.today().year
    latest_zipfile = os.path.join(nvddir,
                                  "nvdcve-1.0-" + str(this_year) + ".json.zip")

    if not os.path.isfile(latest_zipfile) or (datetime.datetime.today() - datetime.datetime.fromtimestamp(os.path.getmtime(latest_zipfile))) > datetime.timedelta(hours=24):
        get_cvelist(nvddir, dbname)

    if not os.path.isfile(dbname):
        conn = init_database(dbname)
        cve_number, vendor_name, product_name, exploitability_score, impact_score, severity, versions = extract_data(nvddir)
        store_cve_data(conn, cve_number, vendor_name, product_name, exploitability_score, impact_score, severity, versions)
        conn.close()

    else:
        print("Last Update: " + datetime.date.fromtimestamp(os.path.getmtime(dbname)).isoformat())
        print("Local database has been updated in the past 24h.")
        print("New data not downloaded.  Remove old files to force the update.")

    #conn = init_database(dbname)
    #cve_number, vendor_name, product_name, exploitability_score, impact_score, severity, versions = extract_data()
    #store_cve_data(conn, cve_number, vendor_name, product_name, exploitability_score, impact_score, severity, versions)
    #display_data(conn)
    #conn.close()

class NVDSQLite(object):

    def __init__(self, disk_location=DISK_LOCATION_DEFAULT):
        """ Set location on disk where NVD data cache will reside.
        Connect to SQLite database"""
        self.disk_location = disk_location
        self.conn = None

    @property
    def dbname(self):
        """ SQLite datebase file where imported NVD data is stored."""
        return os.path.join(self.disk_location, DBNAME)

    @property
    def nvddir(self):
        """ Directory where NVD zipfiles are stored."""
        return os.path.join(self.disk_location, 'nvd')

    def open(self):
        """ Opens connection to sqlite database."""
        self.conn = sqlite3.connect(self.dbname)

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
            nvd.get_cves(('haxx', 'curl'))
            nvd.get_cves(('haxx', 'curl'), ('rubygems', 'curl'))
        """
        cur = self.conn.cursor()
        query = "SELECT CVE_Number, version, Severity FROM nvd_data WHERE " + \
                " OR ".join(itertools.chain(["(Vendor_Name=? AND Product_Name=?)"] * \
                                             len(vendor_product_pairs)))
        if len(vendor_product_pairs) == 1:
            cur.execute(query, vendor_product_pairs[0])
        else:
            cur.execute(query, tuple(itertools.chain(*vendor_product_pairs)))
        return list(map(CVE._make, cur.fetchall()))

    def get_cvelist_if_stale(self):
        """ Update CVEs data from NVD if stale."""
        get_cvelist_if_stale(self.nvddir, self.dbname)
