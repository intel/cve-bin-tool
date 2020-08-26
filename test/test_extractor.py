""" CVE Binary Tool tests for the extractor function """
import lzma
import os
import shutil
import tarfile
import tempfile
import unittest
from io import BytesIO
from zipfile import ZipFile, ZipInfo

import pytest

from cve_bin_tool.extractor import Extractor
from cve_bin_tool.util import inpath
from .utils import download_file, CURL_7_20_0_URL, VMWARE_CAB, TMUX_DEB, event_loop

# Enable logging if tests are not passing to help you find errors
# import logging
# logging.basicConfig(level=logging.DEBUG)


class TestExtractorBase:
    """Test methods for extraction of various file types"""

    @classmethod
    def setup_class(cls):
        cls.extractor = Extractor()
        cls.tempdir = tempfile.mkdtemp(prefix="cve-bin-tool-")

    @classmethod
    def teardown_class(cls):
        shutil.rmtree(cls.tempdir)

    @pytest.mark.asyncio
    async def extract_files(self, filenames):
        """ Make sure all test files are present """
        for filename in filenames:
            assert os.path.exists(
                os.path.join(self.tempdir, filename)
            ), f"test file {filename} was not found"
        # Make sure extraction reports success
        for filename in filenames:
            async with self.extractor as ectx:
                yield await ectx.aio_extract(os.path.join(self.tempdir, filename))


class TestExtractor(TestExtractorBase):
    """ Test methods for the extractor functionality """

    def test_can_extract(self):
        """ Test that the can_extract function knows what it can do """
        assert self.extractor.can_extract(".tar.bz2")
        assert self.extractor.can_extract(".zip")
        assert self.extractor.can_extract(".deb")


class TestExtractFileTar(TestExtractorBase):
    """ Tetss for tar file extraction """

    def setup_method(self):
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
        tarpath = os.path.join(self.tempdir, "test.tar")
        tarpath_xz = os.path.join(self.tempdir, "test.tar.xz")
        with open(tarpath, "rb") as infile, lzma.open(tarpath_xz, "w") as outfile:
            outfile.write(infile.read())

    @pytest.mark.asyncio
    async def test_extract_file_tar(self):
        """ Test the tar file extraction """
        async for path in self.extract_files(
            [
                "test" + e
                for e in self.extractor.file_extractors[self.extractor.extract_file_tar]
            ]
        ):
            assert os.path.isdir(path)

    @pytest.mark.asyncio
    async def test_extract_cleanup(self):
        """ Make sure tar extractor cleans up after itself """
        async with self.extractor as ectx:
            extracted_path = await ectx.aio_extract(
                os.path.join(self.tempdir, "test.tar")
            )
            assert os.path.isdir(extracted_path)
        assert not os.path.exists(extracted_path)


class TestExtractFileRpm(TestExtractorBase):
    """ Tests for the rpm file extractor """

    def setup_method(self):
        download_file(CURL_7_20_0_URL, os.path.join(self.tempdir, "test.rpm"))

    @pytest.mark.asyncio
    async def test_extract_file_rpm(self):
        """ Test the rpm file extraction """
        async for extracted_path in self.extract_files(
            [
                "test" + e
                for e in self.extractor.file_extractors[self.extractor.extract_file_rpm]
            ]
        ):
            assert os.path.isfile(os.path.join(extracted_path, "usr", "bin", "curl"))


class TestExtractFileDeb(TestExtractorBase):
    """ Tests for deb file extractor """

    def setup_method(self):
        assert inpath("ar"), "Required tool 'ar' not found"
        download_file(TMUX_DEB, os.path.join(self.tempdir, "test.deb"))
        shutil.copyfile(
            os.path.join(self.tempdir, "test.deb"),
            os.path.join(self.tempdir, "test.ipk"),
        )

    @pytest.mark.asyncio
    async def test_extract_file_deb(self):
        """ Test the deb file extraction """
        async for extracted_path in self.extract_files(
            [
                "test" + e
                for e in self.extractor.file_extractors[self.extractor.extract_file_deb]
            ]
        ):
            assert os.path.isfile(os.path.join(extracted_path, "usr", "bin", "tmux"))


class TestExtractFileCab(TestExtractorBase):
    """ Tests for the cab file extractor """

    def setup_method(self):
        download_file(VMWARE_CAB, os.path.join(self.tempdir, "test.cab"))

    @unittest.skipUnless(
        os.getenv("ACTIONS") != "1", "Skipping tests that cannot pass in github actions"
    )
    @pytest.mark.asyncio
    async def test_extract_file_cab(self):
        """ Test the cab file extraction """
        async for extracted_path in self.extract_files(
            [
                "test" + e
                for e in self.extractor.file_extractors[self.extractor.extract_file_cab]
            ]
        ):
            assert os.path.isfile(os.path.join(extracted_path, "vmware.htm"))


class TestExtractFileZip(TestExtractorBase):
    """Tests for the zip file extractor
    This extractor also handles jar, apk, and sometimes exe files
    when the exe is a self-extracting zipfile"""

    def setup_method(self):
        for filename in [
            "test.exe",
            "test.zip",
            "test.jar",
            "test.apk",
            "test.msi",
            "test.egg",
            "test.whl",
        ]:
            zippath = os.path.join(self.tempdir, filename)
            with ZipFile(zippath, "w") as zipfile:
                zipfile.writestr(ZipInfo("test.txt"), "feedface")

    @pytest.mark.asyncio
    async def test_extract_file_zip(self):
        """ Test the zip file extraction """
        async for path in self.extract_files(
            [
                "test" + e
                for e in self.extractor.file_extractors[self.extractor.extract_file_zip]
            ]
        ):
            assert os.path.isdir(path)
