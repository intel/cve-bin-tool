"""
CVE-bin-tool tests
"""
import os
import sys
import ssl
import shutil
import stat
import tempfile
import unittest
import subprocess
from multiprocessing import Process
from contextlib import contextmanager
if sys.version_info.major == 2:
    from BaseHTTPServer import HTTPServer
    from SimpleHTTPServer import SimpleHTTPRequestHandler
    from urllib2 import URLError
else:
    from urllib.error import URLError
    from http.server import HTTPServer, \
                            SimpleHTTPRequestHandler

from cve_bin_tool.NVDAutoUpdate import NVDSQLite, DBNAME, CREATE_SYNTAX, CVE, \
        get_cvelist

def run_https_server(keyfile, certfile, port):
    httpd = HTTPServer(('127.0.0.1', port), SimpleHTTPRequestHandler)
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    ctx.load_cert_chain(certfile, keyfile=keyfile)
    httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True)
    httpd.serve_forever()

@contextmanager
def test_https_server(tempdir, port):
    keyfile = os.path.join(tempdir, 'key.pem')
    certfile = os.path.join(tempdir, 'cert.pem')
    subprocess.call(['openssl', 'req', '-x509', '-newkey', 'rsa:1024',
                     '-keyout', keyfile, '-out', certfile, '-days', '1',
                     '-nodes', '-sha256', '-subj',
                     '/C=US/ST=Oregon/L=Portland/O=Intel/OU=Org/CN=127.0.0.1'])

    proc = Process(target=run_https_server, args=(keyfile, certfile, port,))
    proc.start()
    try:
        yield certfile
    finally:
        proc.terminate()
        proc.join()

class TestNVD(unittest.TestCase):
    """ Tests NVD file."""

    @classmethod
    def setUpClass(cls):
        cls.tempdir = tempfile.mkdtemp(prefix='cve-bin-tool-')
        cls.nvddir = os.path.join(cls.tempdir, 'nvd')
        cls.dbname = os.path.join(cls.tempdir, DBNAME)

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tempdir)

    @unittest.skipUnless(os.getenv('LONG_TESTS') == '1', 'Skipping long tests')
    def test_get_cvelist(self):
        get_cvelist(self.nvddir, self.dbname)
        self.assertTrue(os.path.isdir(self.nvddir))
        self.assertTrue(os.path.isfile(self.dbname))

    def test_ssl(self):
        port = 32983
        with test_https_server(self.tempdir, port) as certfile:
            ctx = ssl.create_default_context()
            ctx.load_verify_locations(cafile=certfile)
            get_cvelist(self.nvddir, self.dbname,
                        json_feed='https://127.0.0.1:%d/' % (port,),
                        json_zip='https://127.0.0.1:%d/' % (port,),
                        context=ctx)

    def test_ssl_failure(self):
        port = 32983
        with test_https_server(self.tempdir, port) as certfile:
            with self.assertRaises(URLError):
                get_cvelist(self.nvddir, self.dbname,
                            json_feed='https://127.0.0.1:%d/' % (port,),
                            json_zip='https://127.0.0.1:%d/' % (port,))

class TestNVDSQLite(unittest.TestCase):
    """ Tests NVDSQLite class."""

    @classmethod
    def setUpClass(cls):
        cls.tempdir = tempfile.mkdtemp(prefix='cve-bin-tool-')
        cls.nvd = NVDSQLite(cls.tempdir)

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tempdir)

    def test_dbname(self):
        self.assertEqual(self.nvd.dbname, os.path.join(self.tempdir, DBNAME))

    def test_nvddir(self):
        self.assertEqual(self.nvd.nvddir, os.path.join(self.tempdir, 'nvd'))

    def test_open_close(self):
        with self.nvd:
            self.assertNotEqual(self.nvd.conn, None)
        self.assertEqual(self.nvd.conn, None)

    def test_file_permissions(self):
        # Since we are pointed at a tempdir make sure the dbfile in the tempdir
        # is created before checking permissions by using with nvd.
        with self.nvd:
            # User should be able to read/write the dbfile
            self.assertNotEqual(os.stat(self.nvd.dbname).st_mode & stat.S_IRUSR, 0)
            self.assertNotEqual(os.stat(self.nvd.dbname).st_mode & stat.S_IWUSR, 0)

            # Others should not be able to write/execute the dbfile
            self.assertEqual(os.stat(self.nvd.dbname).st_mode & stat.S_IXOTH, 0)
            self.assertEqual(os.stat(self.nvd.dbname).st_mode & stat.S_IWOTH, 0)

    def test_get_cves(self):
        check = [('CVE-001', 'example0', 'app0'),
                 ('CVE-002', 'example1', 'app1')]
        with self.nvd:
            c = self.nvd.conn.cursor()
            c.execute(CREATE_SYNTAX)
            for cve in check:
                c.execute('''INSERT INTO nvd_data(
                             CVE_Number, Vendor_Name, Product_Name)
                             VALUES(?,?,?)''', cve)
            self.nvd.conn.commit()
            # Check that single select works
            for cve in check:
                found = self.nvd.get_cves(cve[1:])
                self.assertEqual(len(found), 1)
                self.assertEqual(found[0].number, cve[0])
            # Check that multi select works
            found = self.nvd.get_cves(*[cve[1:] for cve in check])
            self.assertEqual(len(found), 2)
