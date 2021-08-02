# Copyright (C) 2021 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later

""" CVE Binary Tool tests for the extractor function """
import lzma
import os
import shutil
import tarfile
import tempfile
import unittest
import unittest.mock
from io import BytesIO
from test.utils import CURL_7_20_0_URL, TMUX_DEB, download_file, event_loop
from zipfile import ZipFile, ZipInfo

import pytest

from cve_bin_tool.extractor import Extractor
from cve_bin_tool.util import inpath

# Enable logging if tests are not passing to help you find errors
# import logging
# logging.basicConfig(level=logging.DEBUG)

CAB_TEST_FILE_PATH = os.path.join(
    os.path.join(os.path.abspath(os.path.dirname(__file__)), "assets"),
    "cab-test-python3.8.cab",
)
BAD_EXE_FILE = os.path.join(
    os.path.join(os.path.abspath(os.path.dirname(__file__)), "assets"),
    "empty-file.exe",
)
BAD_ZIP_FILE = os.path.join(
    os.path.join(os.path.abspath(os.path.dirname(__file__)), "assets"),
    "empty-file.zip",
)


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
        """Make sure all test files are present"""
        for filename in filenames:
            assert os.path.exists(
                os.path.join(self.tempdir, filename)
            ), f"test file {filename} was not found"
        # Make sure extraction reports success
        for filename in filenames:
            async with self.extractor as ectx:
                yield await ectx.aio_extract(os.path.join(self.tempdir, filename))


class TestExtractor(TestExtractorBase):
    """Test methods for the extractor functionality"""

    def test_can_extract(self):
        """Test that the can_extract function knows what it can do"""
        assert self.extractor.can_extract(".tar.bz2")
        assert self.extractor.can_extract(".zip")
        assert self.extractor.can_extract(".deb")


class TestExtractFileTar(TestExtractorBase):
    """Tetss for tar file extraction"""

    def setup_method(self):
        for filename, tarmode in [
            ("test.tgz", "w:gz"),
            ("test.tar.gz", "w:gz"),
            ("test.tar.bz2", "w:bz2"),
            ("test.tar", "w"),
        ]:
            tarpath = os.path.join(self.tempdir, filename)
            tar = tarfile.open(tarpath, mode=tarmode)
            data = b"feedface"
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
        """Test the tar file extraction"""
        async for path in self.extract_files(
            [
                "test" + e
                for e in self.extractor.file_extractors[self.extractor.extract_file_tar]
            ]
        ):
            assert os.path.isdir(path)

    @pytest.mark.asyncio
    async def test_extract_cleanup(self):
        """Make sure tar extractor cleans up after itself"""
        async with self.extractor as ectx:
            extracted_path = await ectx.aio_extract(
                os.path.join(self.tempdir, "test.tar")
            )
            assert os.path.isdir(extracted_path)
        assert not os.path.exists(extracted_path)


class TestExtractFileRpm(TestExtractorBase):
    """Tests for the rpm file extractor"""

    @classmethod
    def setup_class(cls):
        super().setup_class()
        download_file(CURL_7_20_0_URL, os.path.join(cls.tempdir, "test.rpm"))

    @pytest.mark.asyncio
    async def test_extract_file_rpm(self):
        """Test the rpm file extraction"""
        async for extracted_path in self.extract_files(
            [
                "test" + e
                for e in self.extractor.file_extractors[self.extractor.extract_file_rpm]
            ]
        ):
            assert os.path.isfile(os.path.join(extracted_path, "usr", "bin", "curl"))

    @pytest.mark.asyncio
    async def test_extract_file_rpm_no_rpm2cipo(self):
        """Test rpm extraction using rpmfile"""
        with unittest.mock.patch(
            "cve_bin_tool.async_utils.aio_inpath",
            return_value=False,
        ), unittest.mock.patch(
            "cve_bin_tool.async_utils.aio_run_command",
        ) as mock_aio_run_command:
            await self.test_extract_file_rpm()
            mock_aio_run_command.assert_not_called()


class TestExtractFileDeb(TestExtractorBase):
    """Tests for deb file extractor"""

    def setup_method(self):
        assert inpath("ar"), "Required tool 'ar' not found"
        download_file(TMUX_DEB, os.path.join(self.tempdir, "test.deb"))
        shutil.copyfile(
            os.path.join(self.tempdir, "test.deb"),
            os.path.join(self.tempdir, "test.ipk"),
        )

    @pytest.mark.asyncio
    async def test_extract_file_deb(self):
        """Test the deb file extraction"""
        async for extracted_path in self.extract_files(
            [
                "test" + e
                for e in self.extractor.file_extractors[self.extractor.extract_file_deb]
            ]
        ):
            assert os.path.isfile(os.path.join(extracted_path, "usr", "bin", "tmux"))


class TestExtractFileCab(TestExtractorBase):
    """Tests for the cab file extractor"""

    def setup_method(self):
        shutil.copyfile(CAB_TEST_FILE_PATH, os.path.join(self.tempdir, "test.cab"))

    @pytest.mark.asyncio
    async def test_extract_file_cab(self):
        """Test the cab file extraction"""
        async for extracted_path in self.extract_files(
            [
                "test" + e
                for e in self.extractor.file_extractors[self.extractor.extract_file_cab]
            ]
        ):

            assert os.path.isfile(
                os.path.join(
                    os.path.join(os.path.join(extracted_path, "usr"), "bin"),
                    "python3.8",
                )
            )


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
        """Test the zip file extraction"""
        async for path in self.extract_files(
            [
                "test" + e
                for e in self.extractor.file_extractors[self.extractor.extract_file_zip]
            ]
        ):
            assert os.path.isdir(path)

    @pytest.mark.asyncio
    async def test_bad_zip(self):
        """Test handling of invalid zip files.  No errors should be raised.
        Log messages differ for .exe and .zip and are tested in test_cli.py
        """

        self.extract_files(BAD_EXE_FILE)
        self.extract_files(BAD_ZIP_FILE)
