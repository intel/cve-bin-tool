# Copyright (C) 2022 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later

""" CVE Binary Tool tests for the extractor function """
from __future__ import annotations

import shutil
import sys
import tarfile
import tempfile
import unittest
import unittest.mock
from io import BytesIO
from pathlib import Path
from test.utils import (
    APK_FILE_PATH,
    CAB_TEST_FILE_PATH,
    CURL_7_20_0_URL,
    DEB_FILE_PATH,
    DEB_ZST_FILE_PATH,
    DOVECOT_FILE_PATH,
    IPK_FILE_PATH,
    PKG_FILE_PATH,
    ZST_FILE_PATH,
    download_file,
)
from zipfile import ZipFile, ZipInfo

import pytest
from pytest_mock import MockerFixture

from cve_bin_tool.extractor import EXTENSIONS, Extractor
from cve_bin_tool.util import inpath

# Enable logging if tests are not passing to help you find errors
# import logging
# logging.basicConfig(level=logging.DEBUG)


class TestExtractorBase:
    """Test methods for extraction of various file types"""

    tempdir = Path(tempfile.mkdtemp())  # type: Path
    extractor = Extractor()

    @classmethod
    def setup_class(cls):
        cls.extractor = Extractor()
        cls.tempdir = Path(tempfile.mkdtemp(prefix="cve-bin-tool-"))

    @classmethod
    def teardown_class(cls):
        shutil.rmtree(cls.tempdir)

    @pytest.mark.asyncio
    async def extract_files(self, filenames):
        """Make sure all test files are present"""
        for filename in filenames:
            assert (
                self.tempdir / filename
            ).exists(), f"test file {filename} was not found"
        # Make sure extraction reports success
        for filename in filenames:
            async with self.extractor as ectx:
                yield await ectx.aio_extract(str(self.tempdir / filename))

    @pytest.fixture
    def extension_list(self) -> list[str]:
        return []

    @pytest.mark.asyncio
    async def test_bad_files(self, extension_list: list[str]):
        """Test handling of invalid files. No exceptions should be raised."""
        for extension in extension_list:
            filename = self.tempdir / f"empty-file{extension}"
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
            ("test.xz", "w:xz"),
            ("test.bz2", "w:bz2"),
            ("test.gz", "w:gz"),
        ]:
            tarpath = self.tempdir / filename
            tar = tarfile.open(tarpath, mode=tarmode)
            data = b"feedface"
            addfile = BytesIO(data)
            info = tarfile.TarInfo(name="test.txt")
            info.size = len(data)
            tar.addfile(tarinfo=info, fileobj=addfile)
            tar.close()

    @pytest.fixture
    def extension_list(self) -> list[str]:
        return self.extractor.file_extractors[self.extractor.extract_file_tar][
            EXTENSIONS
        ]

    @pytest.mark.asyncio
    async def test_extract_file_tar(self, extension_list: list[str]):
        """Test the tar file extraction"""
        async for dir_path in self.extract_files(
            [f"test{extension}" for extension in extension_list]
        ):
            assert Path(dir_path).is_dir()

    @pytest.mark.asyncio
    async def test_extract_file_tar_absolute(self):
        """Test against a tarfile with absolute file names.
        It should not extract to /tmp/cve-bin-tool_tarfile_test.txt"""

        abs_tar_test = (
            Path(__file__).parent.resolve() / "assets" / "tarfile_abs_test.tar"
        )
        self.extract_files(abs_tar_test)
        assert not Path("/tmp/cve-bin-tool_tarfile_abs_test.txt").is_file()  # nosec
        # Bandit note: intentional hard-coded value for this test of absolute file extraction

    @pytest.mark.asyncio
    async def test_extract_cleanup(self):
        """Make sure tar extractor cleans up after itself"""
        async with self.extractor as ectx:
            extracted_path = await ectx.aio_extract(str(self.tempdir / "test.tar"))
            extracted_path = Path(extracted_path)
            assert extracted_path.is_dir()
        assert not extracted_path.exists()


class TestExtractFileRpm(TestExtractorBase):
    """Tests for the rpm file extractor"""

    @classmethod
    def setup_class(cls):
        super().setup_class()
        download_file(CURL_7_20_0_URL, cls.tempdir / "test.rpm")

    @pytest.fixture
    def extension_list(self) -> list[str]:
        return self.extractor.file_extractors[self.extractor.extract_file_rpm][
            EXTENSIONS
        ]

    @pytest.mark.asyncio
    async def test_extract_file_rpm(self, extension_list: list[str]):
        """Test the rpm file extraction"""
        async for extracted_path in self.extract_files(
            [f"test{extension}" for extension in extension_list]
        ):
            assert (Path(extracted_path) / "usr" / "bin" / "curl").is_file()

    @pytest.mark.asyncio
    async def test_extract_file_rpm_no_rpm2cipo(self, extension_list: list[str]):
        """Test rpm extraction using rpmfile"""
        with unittest.mock.patch(
            "cve_bin_tool.async_utils.aio_inpath",
            return_value=False,
        ), unittest.mock.patch(
            "cve_bin_tool.async_utils.aio_run_command",
        ) as mock_aio_run_command:
            await self.test_extract_file_rpm(extension_list)
            mock_aio_run_command.assert_not_called()


class TestExtractFileZst(TestExtractorBase):
    """Tests for the zst file extractor"""

    def setup_method(self):
        shutil.copyfile(ZST_FILE_PATH, self.tempdir / "test.zst")

    @pytest.fixture
    def extension_list(self) -> list[str]:
        return self.extractor.file_extractors[self.extractor.extract_file_zst][
            EXTENSIONS
        ]

    @pytest.mark.asyncio
    @pytest.mark.skipif(
        sys.platform == "win32", reason="windows zst support incomplete"
    )
    async def test_extract_file_zst(self, extension_list: list[str]):
        """Test the zst file extraction"""
        async for extracted_path in self.extract_files(
            [f"test{extension}" for extension in extension_list]
        ):
            assert (
                Path(extracted_path) / "dir" / "dir2" / "cve_bin_tool_zst_test"
            ).is_file()


class TestExtractFilePkg(TestExtractorBase):
    """Tests for pkg file extractor"""

    def setup_method(self):
        assert inpath("tar") or inpath("7z"), "Required tools 'tar' or '7z' not found"
        shutil.copyfile(PKG_FILE_PATH, self.tempdir / "test.pkg")

    @pytest.fixture
    def extension_list(self) -> list[str]:
        return self.extractor.file_extractors[self.extractor.extract_file_pkg][
            EXTENSIONS
        ]

    @pytest.mark.parametrize(
        "inpath_return_values",
        (
            {"tar": True, "7z": False},  # use `tar` to extract
            {"tar": False, "7z": True},  # use `7z` to extract
        ),
    )
    @pytest.mark.asyncio
    async def test_extract_file_pkg(
        self,
        extension_list: list[str],
        inpath_return_values: dict[str, bool],
        mocker: MockerFixture,
    ):
        """Test the pkg file extraction"""

        mock_func = mocker.AsyncMock(side_effect=inpath_return_values.get)

        mocker.patch("cve_bin_tool.extractor.aio_inpath", mock_func)

        async for extracted_path in self.extract_files(
            [f"test{extension}" for extension in extension_list]
        ):
            assert (
                Path(extracted_path) / "dir" / "dir2" / "cve_bin_tool_pkg_test"
            ).is_file()


class TestExtractFileRpmWithZstd(TestExtractorBase):
    """Tests for the rpm file extractor (zstd/windows)"""

    @classmethod
    def setup_class(cls):
        super().setup_class()
        shutil.copyfile(DOVECOT_FILE_PATH, cls.tempdir / "test.rpm")

    @pytest.fixture
    def extension_list(self) -> list[str]:
        return self.extractor.file_extractors[self.extractor.extract_file_rpm][
            EXTENSIONS
        ]

    @pytest.mark.asyncio
    async def test_extract_file_rpm(self, extension_list: list[str]):
        """Test the rpm file extraction in windows with zstd"""
        async for extracted_path in self.extract_files(
            [f"test{extension}" for extension in extension_list]
        ):
            assert (Path(extracted_path) / "usr" / "sbin" / "dovecot").is_file()


class TestExtractFileDeb(TestExtractorBase):
    """Tests for deb file extractor"""

    def setup_method(self):
        assert inpath("ar"), "Required tool 'ar' not found"
        shutil.copyfile(DEB_FILE_PATH, self.tempdir / "test.deb")
        shutil.copyfile(self.tempdir / "test.deb", self.tempdir / "test.ipk")

    @pytest.fixture
    def extension_list(self) -> list[str]:
        return self.extractor.file_extractors[self.extractor.extract_file_deb][
            EXTENSIONS
        ]

    @pytest.mark.asyncio
    @pytest.mark.skipif(
        sys.version_info[:2] == (3, 11), reason="py3.11 fails sometimes"
    )
    async def test_extract_file_deb(self, extension_list: list[str]):
        """Test the deb file extraction"""
        async for extracted_path in self.extract_files(
            [f"test{extension}" for extension in extension_list]
        ):
            assert (
                Path(extracted_path) / "usr" / "bin" / "cve_bin_tool_deb_test"
            ).is_file()

    @pytest.mark.asyncio
    async def test_extract_file_deb_no_tool(
        self, extension_list: list[str], mocker: MockerFixture
    ):
        """Test the deb file extraction with no extraction tool"""
        mocker.patch("cve_bin_tool.extractor.aio_inpath", return_value=False)
        # will not extract file, but also won't raise an exception
        # we could also check log messages?
        async for extracted_path in self.extract_files(
            [f"test{extension}" for extension in extension_list]
        ):
            assert not (
                Path(extracted_path) / "usr" / "bin" / "cve_bin_tool_deb_test"
            ).is_file()


class TestExtractFileDebWithZstd(TestExtractorBase):
    """Tests for deb file extractor with zstd contents"""

    def setup_method(self):
        assert inpath("ar"), "Required tool 'ar' not found"
        shutil.copyfile(DEB_ZST_FILE_PATH, self.tempdir / "test.deb")
        shutil.copyfile(self.tempdir / "test.deb", self.tempdir / "test.ipk")

    @pytest.fixture
    def extension_list(self) -> list[str]:
        return self.extractor.file_extractors[self.extractor.extract_file_deb][
            EXTENSIONS
        ]

    @pytest.mark.asyncio
    @pytest.mark.skipif(
        sys.version_info.major == 3 and (sys.version_info.minor in (7, 11)),
        reason="py3.7 and py3.11 fail sometimes",
    )
    @pytest.mark.skipif(
        sys.platform == "win32", reason="windows zst support incomplete"
    )
    async def test_extract_file_deb(self, extension_list: list[str]):
        """Test the deb file extraction"""
        async for extracted_path in self.extract_files(
            [f"test{extension}" for extension in extension_list]
        ):
            assert (
                Path(extracted_path) / "usr" / "bin" / "cve_bin_tool_deb_test"
            ).is_file()

    @pytest.mark.asyncio
    async def test_extract_file_deb_no_tool(
        self, extension_list: list[str], mocker: MockerFixture
    ):
        """Test the deb file extraction with no extraction tool"""
        mocker.patch("cve_bin_tool.extractor.aio_inpath", return_value=False)
        # will not extract file, but also won't raise an exception
        # we could also check log messages?
        async for extracted_path in self.extract_files(
            [f"test{extension}" for extension in extension_list]
        ):
            assert not (
                Path(extracted_path) / "usr" / "bin" / "cve_bin_tool_deb_test"
            ).is_file()


class TestExtractFileIpk(TestExtractorBase):
    """Tests for ipk file extractor"""

    def setup_method(self):
        assert inpath("ar"), "Required tool 'ar' not found"
        shutil.copyfile(DEB_FILE_PATH, self.tempdir / "test.deb")
        shutil.copyfile(IPK_FILE_PATH, self.tempdir / "test.ipk")

    @pytest.fixture
    def extension_list(self) -> list[str]:
        return self.extractor.file_extractors[self.extractor.extract_file_deb][
            EXTENSIONS
        ]

    @pytest.mark.asyncio
    @pytest.mark.skipif(
        sys.version_info[:2] == (3, 11), reason="py3.11 fails sometimes"
    )
    async def test_extract_file_ipk(self, extension_list: list[str]):
        """Test the ipk file extraction"""
        async for extracted_path in self.extract_files(
            [f"test{extension}" for extension in extension_list]
        ):
            assert (
                Path(extracted_path) / "usr" / "bin" / "cve_bin_tool_deb_test"
            ).is_file()


class TestExtractFileCab(TestExtractorBase):
    """Tests for the cab file extractor"""

    def setup_method(self):
        shutil.copyfile(CAB_TEST_FILE_PATH, self.tempdir / "test.cab")

    @pytest.fixture
    def extension_list(self) -> list[str]:
        return self.extractor.file_extractors[self.extractor.extract_file_cab][
            EXTENSIONS
        ]

    @pytest.mark.asyncio
    async def test_extract_file_cab(self, extension_list: list[str]):
        """Test the cab file extraction"""
        async for extracted_path in self.extract_files(
            [f"test{extension}" for extension in extension_list]
        ):
            assert (Path(extracted_path) / "usr" / "bin" / "python3.8").is_file()

    @pytest.mark.asyncio
    async def test_extract_file_cab_no_cabextract(
        self, extension_list: list[str], mocker: MockerFixture
    ):
        """Test the cab file extraction with no extraction tool"""

        mocker.patch("cve_bin_tool.extractor.aio_inpath", return_value=False)

        # will not raise exception but also will not extract file
        # could also check log messages here?
        async for extracted_path in self.extract_files(
            [f"test{extension}" for extension in extension_list]
        ):
            assert not (Path(extracted_path) / "usr" / "bin" / "python3.8").is_file()


class TestExtractFileZip(TestExtractorBase):
    """Tests for the zip file extractor
    This extractor also handles jar, apk, and sometimes exe files
    when the exe is a self-extracting zipfile"""

    @pytest.fixture
    def extension_list(self) -> list[str]:
        return list(
            self.extractor.file_extractors[self.extractor.extract_file_apk][EXTENSIONS]
            + self.extractor.file_extractors[self.extractor.extract_file_zip][
                EXTENSIONS
            ]
        )

    @pytest.fixture(autouse=True)
    def setup_method(self, extension_list: list[str]):
        for filename in [f"test{extension}" for extension in extension_list]:
            zippath = self.tempdir / filename
            with ZipFile(zippath, "w") as zipfile:
                zipfile.writestr(ZipInfo("test.txt"), "feedface")

    @pytest.mark.parametrize(
        "inpath_return_values",
        (
            {"unzip": True, "7z": False, "zipinfo": False, "file": False},
            {"unzip": False, "7z": True, "zipinfo": False, "file": False},
            {"unzip": False, "7z": False, "zipinfo": True, "file": False},
            {"unzip": False, "7z": False, "zipinfo": False, "file": True},
        ),
    )
    @pytest.mark.asyncio
    async def test_extract_file_zip(
        self,
        extension_list: list[str],
        inpath_return_values: dict[str, bool],
        mocker: MockerFixture,
    ):
        """Test the zip file extraction"""

        mock_func = mocker.AsyncMock(side_effect=inpath_return_values.get)

        mocker.patch("cve_bin_tool.extractor.aio_inpath", mock_func)

        async for dir_path in self.extract_files(
            [f"test{extension}" for extension in extension_list]
        ):
            assert Path(dir_path).is_dir()


class TestExtractFileApk(TestExtractorBase):
    """Test for apk file extractor"""

    @classmethod
    def setup_class(cls):
        super().setup_class()
        shutil.copyfile(APK_FILE_PATH, cls.tempdir / "test.apk")

    @pytest.fixture
    def extension_list(self) -> list[str]:
        return self.extractor.file_extractors[self.extractor.extract_file_apk][
            EXTENSIONS
        ]

    @pytest.mark.asyncio
    async def test_extract_file_apk(self, extension_list: list[str]):
        async for extracted_path in self.extract_files(
            [f"test{extension}" for extension in extension_list]
        ):
            assert (Path(extracted_path) / "test-curl-7.34.0.out").is_file()
