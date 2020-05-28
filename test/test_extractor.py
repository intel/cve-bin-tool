""" CVE Binary Tool tests for the extractor function """
import os
import shutil
import sys
import tarfile
import tempfile
import unittest
from io import BytesIO
from zipfile import ZipFile, ZipInfo

from cve_bin_tool.extractor import Extractor
from cve_bin_tool.util import inpath
from .utils import download_file, CURL_7_20_0_URL, VMWARE_CAB, TMUX_DEB

if sys.version_info.major == 3 and sys.version_info.minor >= 3:
    import lzma


# Enable logging if tests are not passing to help you find errors
# import logging
# logging.basicConfig(level=logging.DEBUG)


class TestExtractorBase(unittest.TestCase):
    """Test methods for extraction of various file types"""

    @classmethod
    def setUpClass(cls):
        cls.extractor = Extractor()
        cls.tempdir = tempfile.mkdtemp(prefix="cve-bin-tool-")

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tempdir)

    def extract_files(self, filenames):
        """ Make sure all test files are present """
        for filename in filenames:
            self.assertTrue(
                os.path.exists(os.path.join(self.tempdir, filename)),
                "test file %r was not found" % (filename,),
            )
        # Make sure extraction reports success
        for filename in filenames:
            with self.extractor() as ectx:
                yield ectx.extract(os.path.join(self.tempdir, filename))


class TestExtractor(TestExtractorBase):
    """ Test methods for the extractor functionality """

    def test_can_extract(self):
        """ Test that the can_extract function knows what it can do """
        self.assertTrue(self.extractor.can_extract(".tar.bz2"))
        self.assertTrue(self.extractor.can_extract(".zip"))
        self.assertTrue(self.extractor.can_extract(".deb"))


class TestExtractFileTar(TestExtractorBase):
    """ Tetss for tar file extraction """

    def setUp(self):
        for filename, tarmode in [
            ("test.tgz", "w:gz"),
            ("test.tar.gz", "w:gz"),
            ("test.tar.bz2", "w:bz2"),
            ("test.tar", "w"),
        ]:
            tarpath = os.path.join(self.tempdir, filename)
            tar = tarfile.open(tarpath, mode=tarmode)
            data = "feedface".encode("utf-8")
            addfile = BytesIO(data)
            info = tarfile.TarInfo(name="test.txt")
            info.size = len(data)
            tar.addfile(tarinfo=info, fileobj=addfile)
            tar.close()
        if sys.version_info.major == 3 and sys.version_info.minor >= 3:
            tarpath = os.path.join(self.tempdir, "test.tar")
            tarpath_xz = os.path.join(self.tempdir, "test.tar.xz")
            with open(tarpath, "rb") as infile, lzma.open(tarpath_xz, "w") as outfile:
                outfile.write(infile.read())

    def test_extract_file_tar(self):
        """ Test the tar file extraction """
        try:
            self.extract_files(
                [
                    "test" + e
                    for e in self.extractor.file_extractors[
                        self.extractor.extract_file_tar
                    ]
                ]
            )
        except AssertionError:
            # Don't if we failed the xz test on versions were we couldn't create
            # the file
            if sys.version_info.major == 3 and sys.version_info.minor >= 3:
                raise

    def test_extract_cleanup(self):
        """ Make sure tar extractor cleans up after itself """
        with self.extractor() as ectx:
            extracted_path = ectx.extract(os.path.join(self.tempdir, "test.tar"))
            self.assertTrue(os.path.isdir(extracted_path))
        self.assertFalse(os.path.exists(extracted_path))


class TestExtractFileRpm(TestExtractorBase):
    """ Tests for the rpm file extractor """

    def setUp(self):
        download_file(CURL_7_20_0_URL, os.path.join(self.tempdir, "test.rpm"))

    def test_extract_file_rpm(self):
        """ Test the rpm file extraction """
        for extracted_path in self.extract_files(
            [
                "test" + e
                for e in self.extractor.file_extractors[self.extractor.extract_file_rpm]
            ]
        ):
            self.assertTrue(
                os.path.isfile(os.path.join(extracted_path, "usr", "bin", "curl"))
            )


class TestExtractFileDeb(TestExtractorBase):
    """ Tests for deb file extractor """

    def setUp(self):
        self.assertTrue(inpath("ar"), msg="Required tool 'ar' not found")
        download_file(TMUX_DEB, os.path.join(self.tempdir, "test.deb"))
        shutil.copyfile(
            os.path.join(self.tempdir, "test.deb"),
            os.path.join(self.tempdir, "test.ipk"),
        )

    def test_extract_file_deb(self):
        """ Test the deb file extraction """
        for extracted_path in self.extract_files(
            [
                "test" + e
                for e in self.extractor.file_extractors[self.extractor.extract_file_deb]
            ]
        ):
            self.assertTrue(
                os.path.isfile(os.path.join(extracted_path, "usr", "bin", "tmux"))
            )


class TestExtractFileCab(TestExtractorBase):
    """ Tests for the cab file extractor """

    def setUp(self):
        download_file(VMWARE_CAB, os.path.join(self.tempdir, "test.cab"))

    @unittest.skipUnless(
        os.getenv("ACTIONS") != "1", "Skipping tests that cannot pass in github actions"
    )
    def test_extract_file_cab(self):
        """ Test the cab file extraction """
        for extracted_path in self.extract_files(
            [
                "test" + e
                for e in self.extractor.file_extractors[self.extractor.extract_file_cab]
            ]
        ):
            self.assertTrue(os.path.isfile(os.path.join(extracted_path, "vmware.htm")))


class TestExtractFileZip(TestExtractorBase):
    """ Tests for the zip file extractor
        This extractor also handles jar, apk, and sometimes exe files
        when the exe is a self-extracting zipfile """

    def setUp(self):
        for filename in ["test.exe", "test.zip", "test.jar", "test.apk"]:
            zippath = os.path.join(self.tempdir, filename)
            with ZipFile(zippath, "w") as zipfile:
                zipfile.writestr(ZipInfo("test.txt"), "feedface")

    def test_extract_file_zip(self):
        """ Test the zip file extraction """
        self.extract_files(
            [
                "test" + e
                for e in self.extractor.file_extractors[self.extractor.extract_file_zip]
            ]
        )
