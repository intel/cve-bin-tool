# Copyright (C) 2021 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later

""" CVE Binary Tool tests for the extractor function """
import shutil
import tarfile
import tempfile
import unittest
import unittest.mock
from io import BytesIO
from os import path
from test.utils import CURL_7_20_0_URL, TMUX_DEB, download_file
from typing import List
from zipfile import ZipFile, ZipInfo

import pytest

from cve_bin_tool.extractor import Extractor
from cve_bin_tool.util import inpath

# Enable logging if tests are not passing to help you find errors
# import logging
# logging.basicConfig(level=logging.DEBUG)

CAB_TEST_FILE_PATH = path.join(
    path.abspath(path.dirname(__file__)), "assets", "cab-test-python3.8.cab"
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
            assert path.exists(
                path.join(self.tempdir, filename)
            ), f"test file {filename} was not found"
        # Make sure extraction reports success
        for filename in filenames:
            async with self.extractor as ectx:
                yield await ectx.aio_extract(path.join(self.tempdir, filename))

    @pytest.fixture
    def extension_list(self) -> List[str]:
        return []

    @pytest.mark.asyncio
    async def test_bad_files(self, extension_list: List[str]):
        """Test handling of invalid files. No exceptions should be raised."""
        for extension in extension_list:
            filename = path.join(self.tempdir, f"empty-file{extension}")
            # creates an empty file with the expected extension
            open(filename, "w").close()
            async for _ in self.extract_files([filename]):
                pass


class TestExtractFileTar(TestExtractorBase):
    """Tests for tar file extraction"""

    def setup_method(self):
        for filename, tarmode in [
            ("test.tgz", "w:gz"),
            ("test.tar.gz", "w:gz"),
            ("test.tar.bz2", "w:bz2"),
            ("test.tar", "w"),
            ("test.tar.xz", "w:xz"),
        ]:
            tarpath = path.join(self.tempdir, filename)
            tar = tarfile.open(tarpath, mode=tarmode)
            data = b"feedface"
            addfile = BytesIO(data)
            info = tarfile.TarInfo(name="test.txt")
            info.size = len(data)
            tar.addfile(tarinfo=info, fileobj=addfile)
            tar.close()

    @pytest.fixture
    def extension_list(self) -> List[str]:
        return self.extractor.file_extractors[self.extractor.extract_file_tar]

    @pytest.mark.asyncio
    async def test_extract_file_tar(self, extension_list: List[str]):
        """Test the tar file extraction"""
        async for dir_path in self.extract_files(
            [f"test{extension}" for extension in extension_list]
        ):
            assert path.isdir(dir_path)

    @pytest.mark.asyncio
    async def test_extract_cleanup(self):
        """Make sure tar extractor cleans up after itself"""
        async with self.extractor as ectx:
            extracted_path = await ectx.aio_extract(path.join(self.tempdir, "test.tar"))
            assert path.isdir(extracted_path)
        assert not path.exists(extracted_path)


class TestExtractFileRpm(TestExtractorBase):
    """Tests for the rpm file extractor"""

    @classmethod
    def setup_class(cls):
        super().setup_class()
        download_file(CURL_7_20_0_URL, path.join(cls.tempdir, "test.rpm"))

    @pytest.fixture
    def extension_list(self) -> List[str]:
        return self.extractor.file_extractors[self.extractor.extract_file_rpm]

    @pytest.mark.asyncio
    async def test_extract_file_rpm(self, extension_list: List[str]):
        """Test the rpm file extraction"""
        async for extracted_path in self.extract_files(
            [f"test{extension}" for extension in extension_list]
        ):
            assert path.isfile(path.join(extracted_path, "usr", "bin", "curl"))

    @pytest.mark.asyncio
    async def test_extract_file_rpm_no_rpm2cipo(self, extension_list: List[str]):
        """Test rpm extraction using rpmfile"""
        with unittest.mock.patch(
            "cve_bin_tool.async_utils.aio_inpath",
            return_value=False,
        ), unittest.mock.patch(
            "cve_bin_tool.async_utils.aio_run_command",
        ) as mock_aio_run_command:
            await self.test_extract_file_rpm(extension_list)
            mock_aio_run_command.assert_not_called()


class TestExtractFileDeb(TestExtractorBase):
    """Tests for deb file extractor"""

    def setup_method(self):
        assert inpath("ar"), "Required tool 'ar' not found"
        download_file(TMUX_DEB, path.join(self.tempdir, "test.deb"))
        shutil.copyfile(
            path.join(self.tempdir, "test.deb"), path.join(self.tempdir, "test.ipk")
        )

    @pytest.fixture
    def extension_list(self) -> List[str]:
        return self.extractor.file_extractors[self.extractor.extract_file_deb]

    @pytest.mark.asyncio
    async def test_extract_file_deb(self, extension_list: List[str]):
        """Test the deb file extraction"""
        async for extracted_path in self.extract_files(
            [f"test{extension}" for extension in extension_list]
        ):
            assert path.isfile(path.join(extracted_path, "usr", "bin", "tmux"))


class TestExtractFileCab(TestExtractorBase):
    """Tests for the cab file extractor"""

    def setup_method(self):
        shutil.copyfile(CAB_TEST_FILE_PATH, path.join(self.tempdir, "test.cab"))

    @pytest.fixture
    def extension_list(self) -> List[str]:
        return self.extractor.file_extractors[self.extractor.extract_file_cab]

    @pytest.mark.asyncio
    async def test_extract_file_cab(self, extension_list: List[str]):
        """Test the cab file extraction"""
        async for extracted_path in self.extract_files(
            [f"test{extension}" for extension in extension_list]
        ):
            assert path.isfile(path.join(extracted_path, "usr", "bin", "python3.8"))


class TestExtractFileZip(TestExtractorBase):
    """Tests for the zip file extractor
    This extractor also handles jar, apk, and sometimes exe files
    when the exe is a self-extracting zipfile"""

    @pytest.fixture
    def extension_list(self) -> List[str]:
        return list(
            self.extractor.file_extractors[self.extractor.extract_file_apk]
            | self.extractor.file_extractors[self.extractor.extract_file_zip]
        )

    @pytest.fixture(autouse=True)
    def setup_method(self, extension_list: List[str]):
        for filename in [f"test{extension}" for extension in extension_list]:
            zippath = path.join(self.tempdir, filename)
            with ZipFile(zippath, "w") as zipfile:
                zipfile.writestr(ZipInfo("test.txt"), "feedface")

    @pytest.mark.asyncio
    async def test_extract_file_zip(self, extension_list: List[str]):
        """Test the zip file extraction"""
        async for dir_path in self.extract_files(
            [f"test{extension}" for extension in extension_list]
        ):
            assert path.isdir(dir_path)
