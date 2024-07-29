# Copyright (C) 2022 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later

"""
Extraction of archives
"""
import os
import re
import shutil
import sys
import tarfile
import tempfile
from pathlib import Path

import filetype
import zstandard
from rpmfile.cli import main as rpmextract

from cve_bin_tool.async_utils import (
    ChangeDirContext,
    FileIO,
    aio_glob,
    aio_inpath,
    aio_makedirs,
    aio_mkdtemp,
    aio_rmdir,
    aio_run_command,
    aio_unpack_archive,
    async_wrap,
    run_coroutine,
)

from .error_handler import (
    ErrorHandler,
    ErrorMode,
    ExtractionFailed,
    ExtractionToolNotFound,
    UnknownArchiveType,
)
from .log import LOGGER

# Run rpmfile in a thread
rpmextract = async_wrap(rpmextract)

# Extractor dictionary keys
EXTENSIONS = "extensions"
MIMES = "mimes"


class BaseExtractor:
    """Extracts tar, rpm, etc. files"""

    def __init__(self, logger=None, error_mode=ErrorMode.TruncTrace):
        # Sets up logger and if we should extract files or just report
        self.logger = logger or LOGGER.getChild(self.__class__.__name__)
        self.error_mode = error_mode
        self.tempdir = None
        # Adding filetype LZMA (see comments on line 438)
        filetype.add_type(Lzma())
        self.file_extractors = {
            self.extract_file_tar: {
                EXTENSIONS: [
                    ".tgz",
                    ".tar.gz",
                    ".tar",
                    ".tar.xz",
                    ".tar.bz2",
                    ".xz",
                    ".bz2",
                    ".gz",
                ],
                MIMES: [
                    "application/x-tar",
                    "appication/gzip",
                ],
            },
            self.extract_file_rpm: {EXTENSIONS: [".rpm"], MIMES: []},
            self.extract_file_deb: {EXTENSIONS: [".deb", ".ipk"], MIMES: []},
            self.extract_file_cab: {EXTENSIONS: [".cab"], MIMES: []},
            self.extract_file_apk: {EXTENSIONS: [".apk"], MIMES: []},
            self.extract_file_zst: {EXTENSIONS: [".zst"], MIMES: []},
            self.extract_file_pkg: {EXTENSIONS: [".pkg"], MIMES: []},
            self.extract_file_zip: {
                EXTENSIONS: [
                    ".exe",
                    ".zip",
                    ".jar",
                    ".msi",
                    ".egg",
                    ".whl",
                    ".war",
                    ".ear",
                ],
                MIMES: [
                    "application/x-msdownload",
                    "application/x-7z-compressed",
                    "application/x-lzip",
                    "application/lzma",
                ],
            },
        }

    def can_extract(self, filename):
        """Check if the filename is something we know how to extract"""
        # Do not try to extract symlinks
        try:
            if Path(filename).is_symlink():
                return False
        except PermissionError:
            return False
        for ext in self.file_extractors:
            if Path(filename).suffix in self.file_extractors[ext][EXTENSIONS]:
                return True
        if os.path.isfile(filename):
            try:
                guess = filetype.guess(filename)
            except PermissionError:
                return False
            for ext in self.file_extractors:
                if guess is not None and guess.MIME in self.file_extractors[ext][MIMES]:
                    return True
        return False

    def tar_member_filter(self, members, extraction_path):
        """Generator function to serve as a backported filter for tarfile extraction
        based on https://docs.python.org/3/library/tarfile.html#examples
        """
        for tarmember in members:
            if tarmember.isfile() and str(
                Path(extraction_path, tarmember.name).resolve()
            ).startsWith(extraction_path):
                yield tarmember

    async def extract_file_tar(self, filename, extraction_path):
        """Extract tar files"""

        # make sure we have full path for later checks
        extraction_path = str(Path(extraction_path).resolve())
        with ErrorHandler(mode=ErrorMode.Ignore) as e:
            # Python 3.12 has a data filter we can use in extract
            # tarfile has this available in older versions as well
            if hasattr(tarfile, "data_filter"):
                with tarfile.open(filename) as tar:
                    tar.extractall(path=extraction_path, filter="data")  # nosec
                # nosec line because bandit doesn't understand filters yet

            elif sys.platform == "win32":
                # Windows users must use python 3.12 or later because the
                # workaround below fails on windows
                # Patches welcome if you can fix this!
                self.logger.error(
                    "Install python 3.12 or later to support tarfile extraction"
                )
                return ExtractionToolNotFound

            # Some versions may need us to implement a filter to avoid unsafe behaviour
            # we could consider logging a warning here
            else:
                with tarfile.open(filename) as tar:
                    tar.extractall(
                        path=extraction_path,
                        members=self.tar_member_filter(tar, extraction_path),
                    )  # nosec

        return e.exit_code

    async def extract_file_rpm(self, filename, extraction_path):
        """Extract rpm packages"""
        extraction_path_pathlib = Path(extraction_path)
        if sys.platform.startswith("linux"):
            if not await aio_inpath("rpm2cpio") or not await aio_inpath("cpio"):
                await rpmextract("-xC", extraction_path, filename)
            else:
                stdout, stderr, _ = await aio_run_command(["rpm2cpio", filename])
                if stderr or not stdout:
                    return 1
                cpio_path = str(extraction_path_pathlib / "data.cpio")
                async with FileIO(cpio_path, "wb") as f:
                    await f.write(stdout)
                stdout, stderr, _ = await aio_run_command(
                    ["cpio", "-idm", "--file", cpio_path]
                )
                if stdout or not stderr:
                    return 1
        else:
            if not await aio_inpath("7z"):
                with ErrorHandler(mode=self.error_mode, logger=self.logger):
                    # ExtractionToolNotFound
                    self.logger.error(f"No extraction tool found for {filename}")
                    self.logger.error("rpm2cpio or 7z can be used to extract rpm files")
            else:
                stdout, stderr, _ = await aio_run_command(["7z", "x", filename])
                if stderr or not stdout:
                    return 1
                filenames = await aio_glob(str(extraction_path_pathlib / "*.cpio"))
                if not filenames:
                    filenames = await aio_glob(
                        str(extraction_path_pathlib / "*.cpio.zstd")
                    )
                    filename = filenames[0]
                    exit_code = await self.extract_file_zst(filename, extraction_path)
                    if exit_code:
                        return 1
                    filenames = await aio_glob(str(extraction_path_pathlib / "*.cpio"))
                filename = filenames[0]
                stdout, stderr, _ = await aio_run_command(["7z", "x", filename])
                if stderr or not stdout:
                    return 1
        return 0

    async def extract_file_zst(self, filename: str, extraction_path: str) -> int:
        """Extract zstd compressed files"""

        dctx = zstandard.ZstdDecompressor()
        with ErrorHandler(mode=ErrorMode.Ignore) as e:
            if filename.endswith(".cpio.zstd"):
                with open(filename, "rb") as compressed:
                    output_path = Path(extraction_path) / Path(filename).stem
                    with open(output_path, "wb") as destination:
                        dctx.copy_stream(compressed, destination)
            else:
                # assume it's a tar.zstd so use tar with unzstd
                if await aio_inpath("tar"):
                    stdout, stderr, _ = await aio_run_command(
                        ["tar", "--use-compress-program=unzstd", "-xvf", filename]
                    )
                    # Assume anything in stderr is bad
                    if stderr:
                        return 1
                elif await aio_inpath("7z"):
                    stdout, stderr, _ = await aio_run_command(["7z", "x", filename])
                    if stderr:
                        return 1
                else:
                    # ExtractionToolNotFound
                    self.logger.error(f"No extraction tool found for {filename}")
                    self.logger.error(
                        "tar or 7zip-zstd is required to extract tar.zstd files"
                    )
        return e.exit_code

    async def extract_file_pkg(self, filename: str, extraction_path: str) -> int:
        """Extract pkg files"""

        async def _extract_through_7z() -> int:
            """Extract file using `7z`"""

            temp = str(Path(self.tempdir) / Path(filename).stem)
            stdout, stderr, _ = await aio_run_command(
                ["7z", "x", filename, f"-o{self.tempdir}"]
            )
            stdout, stderr, _ = await aio_run_command(
                ["7z", "x", temp, f"-o{extraction_path}"]
            )
            if not stdout:
                return 1
            return 0

        if sys.platform.startswith("win"):
            if await aio_inpath("7z"):
                return await _extract_through_7z()

        # Tarfile wasn't used here because it can't open [.pkg] files directy
        # and failed to manage distinct compression types in differnet versions of FreeBSD packages.
        # Reference: https://github.com/intel/cve-bin-tool/pull/1580#discussion_r829346602
        if await aio_inpath("tar"):
            stdout, stderr, return_code = await aio_run_command(
                ["tar", "xf", filename, "-C", extraction_path]
            )
            if (stderr or not stdout) and return_code != 0:
                return 1
            return 0
        if await aio_inpath("7z"):
            return await _extract_through_7z()
        return 1

    async def extract_file_deb(self, filename, extraction_path):
        """Extract debian packages"""
        is_ar = True
        is_zst = False
        process_can_fail = True
        if await aio_inpath("file"):
            stdout, stderr, return_code = await aio_run_command(
                ["file", filename], process_can_fail
            )
            if not re.search(b"Debian binary package", stdout):
                is_ar = False
            if re.search(b"data compression zst", stdout):
                is_zst = True
        if is_ar:
            if not await aio_inpath("ar"):
                with ErrorHandler(mode=self.error_mode, logger=self.logger):
                    # ExtractionToolNotFound
                    self.logger.error(f"No extraction tool found for {filename}")
                    self.logger.error("'ar' is required to extract deb files")
            else:
                stdout, stderr, _ = await aio_run_command(["ar", "x", filename])
                if stderr:
                    return 1
        else:
            self.logger.debug(f"Extracting {filename} as a tar.gzip file")
            with ErrorHandler(mode=ErrorMode.Ignore) as e:
                await aio_unpack_archive(filename, extraction_path, format="gztar")

        datafile = await aio_glob(str(Path(extraction_path) / "data.tar.*"))
        if is_zst:
            return await self.extract_file_zst(datafile[0], extraction_path)
        else:
            with ErrorHandler(mode=ErrorMode.Ignore) as e:
                await aio_unpack_archive(datafile[0], extraction_path)
            return e.exit_code

    async def extract_file_apk(self, filename, extraction_path):
        """Check whether it is alpine or android package"""

        is_tar = True
        process_can_fail = True
        if await aio_inpath("unzip"):
            stdout, stderr, return_code = await aio_run_command(
                ["unzip", "-l", filename], process_can_fail
            )
            if return_code == 0:
                is_tar = False
        elif await aio_inpath("7z"):
            stdout, stderr, return_code = await aio_run_command(
                ["7z", "t", filename], process_can_fail
            )
            if re.search(b"Type = Zip", stdout):
                is_tar = False
        elif await aio_inpath("zipinfo"):
            stdout, stderr, return_code = await aio_run_command(
                ["zipinfo", filename], process_can_fail
            )
            if return_code == 0:
                is_tar = False
        elif await aio_inpath("file"):
            stdout, stderr, return_code = await aio_run_command(
                ["file", filename], process_can_fail
            )
            if re.search(b"Zip archive data", stdout):
                is_tar = False
        if is_tar:
            self.logger.debug(f"Extracting {filename} as a tar.gzip file")
            with ErrorHandler(mode=ErrorMode.Ignore) as e:
                await aio_unpack_archive(filename, extraction_path, format="gztar")
            return e.exit_code
        else:
            return await self.extract_file_zip(filename, extraction_path)

    async def extract_file_cab(self, filename, extraction_path):
        """Extract cab files"""
        if sys.platform.startswith("linux"):
            if not await aio_inpath("cabextract"):
                with ErrorHandler(mode=self.error_mode, logger=self.logger):
                    # ExtractionToolNotFound
                    self.logger.error(f"No extraction tool found for {filename}")
                    self.logger.error("'cabextract' is required to extract cab files")
            else:
                stdout, stderr, _ = await aio_run_command(
                    ["cabextract", "-d", extraction_path, filename]
                )
                if stderr or not stdout:
                    return 1
        else:
            if not await aio_inpath("Expand"):
                with ErrorHandler(mode=self.error_mode, logger=self.logger):
                    # ExtractionToolNotFound
                    self.logger.error(f"No extraction tool found for {filename}")
                    self.logger.error("'Expand' is required to extract cab files")
            else:
                stdout, stderr, _ = await aio_run_command(
                    ["Expand", filename, "-R -F:*", extraction_path]
                )
                if stderr or not stdout:
                    return 1
        return 0

    @staticmethod
    async def extract_file_zip(filename, extraction_path, process_can_fail=True):
        """Extracts ZIP files using an invalid key to prevent
        freezing during extraction if they are password protected.
        Providing a key during extraction has no effect if the zip file is
        not password protected and extraction will happen as normal."""

        is_exe = filename.endswith(".exe")
        key = "StaticInvalidKey"
        if await aio_inpath("unzip"):
            stdout, stderr, _ = await aio_run_command(
                ["unzip", "-P", key, "-n", "-d", extraction_path, filename],
                process_can_fail,
            )
            if stderr:
                if "incorrect password" in stderr.decode():
                    LOGGER.error(
                        f"Failed to extract {filename}: The file is password protected"
                    )
                    return 0
                if is_exe:
                    return 0  # not all .exe files are zipfiles, no need for error
                return 1
        elif await aio_inpath("7z"):
            stdout, stderr, _ = await aio_run_command(
                ["7z", "x", f"-p{key}", filename], process_can_fail
            )
            if stderr or not stdout:
                if "Wrong password" in stderr.decode():
                    LOGGER.error(
                        f"Failed to extract {filename}: The file is password protected"
                    )
                    return 0
                if is_exe:
                    return 0  # not all .exe files are zipfiles, no need for error
                return 1
        else:
            with ErrorHandler(mode=ErrorMode.Ignore) as e:
                await aio_unpack_archive(filename, extraction_path)
            return e.exit_code
        return 0


class TempDirExtractorContext(BaseExtractor):
    """Extracts tar, rpm, etc. files"""

    def __init__(self, raise_failure=False, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.raise_failure = raise_failure

    async def aio_extract(self, filename):
        """Run the extractor"""
        filename_pathlib = Path(filename)
        # Resolve path in case of cwd change
        filename = str(filename_pathlib.resolve())
        for extractor in self.file_extractors:
            for extension in self.file_extractors[extractor][EXTENSIONS]:
                if filename.endswith(extension):
                    extracted_path = str(
                        Path(self.tempdir) / f"{filename_pathlib.name}.extracted"
                    )
                    if Path(extracted_path).exists():
                        await aio_rmdir(extracted_path)
                    await aio_makedirs(extracted_path, 0o700)
                    async with ChangeDirContext(extracted_path):
                        if await extractor(filename, extracted_path) != 0:
                            if self.raise_failure:
                                with ErrorHandler(
                                    mode=self.error_mode, logger=self.logger
                                ):
                                    raise ExtractionFailed(filename)
                            else:
                                self.logger.warning(f"Failure extracting {filename}")
                        else:
                            self.logger.debug(
                                f"Extracted {filename} to {extracted_path}"
                            )
                    return extracted_path
            guess = filetype.guess(filename)
            if (
                guess is not None
                and guess.MIME in self.file_extractors[extractor][MIMES]
            ):
                extracted_path = str(
                    Path(self.tempdir) / f"{filename_pathlib.name}.extracted"
                )
                if Path(extracted_path).exists():
                    await aio_rmdir(extracted_path)
                await aio_makedirs(extracted_path, 0o700)
                async with ChangeDirContext(extracted_path):
                    if await extractor(filename, extracted_path) != 0:
                        if self.raise_failure:
                            with ErrorHandler(mode=self.error_mode, logger=self.logger):
                                raise ExtractionFailed(filename)
                        else:
                            self.logger.warning(f"Failure extracting {filename}")
                    else:
                        self.logger.debug(f"Extracted {filename} to {extracted_path}")
                return extracted_path
        with ErrorHandler(mode=self.error_mode, logger=self.logger):
            raise UnknownArchiveType(filename)

    async def __aenter__(self):
        """Create a temporary directory to extract files to."""
        self.tempdir = await aio_mkdtemp(prefix="cve-bin-tool-")
        return self

    async def __aexit__(self, exc_type, exc, exc_tb):
        """Removes all extraction directories that need to be cleaned up."""
        # removing directory can raise exception so wrap it around ErrorHandler.
        with ErrorHandler(mode=self.error_mode, logger=self.logger):
            await aio_rmdir(self.tempdir)

    def extract(self, filename):
        return run_coroutine(self.aio_extract(filename))

    def __enter__(self):
        self.tempdir = tempfile.mkdtemp(prefix="cve-bin-tool-")
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        with ErrorHandler(mode=self.error_mode, logger=self.logger):
            shutil.rmtree(self.tempdir)


# Creating type LZMA for binary recognition and extraction because cve-bin-tool encounters extraction failure for this filetype
# Using python library filetype defined at https://github.com/h2non/filetype.py
# Following pattern of type creation according to examples in https://github.com/h2non/filetype.py/tree/master/filetype/types
# Adding type LZMA on line 54
class Lzma(filetype.Type):
    """Implements the lzma compression type matcher."""

    MIME = "application/lzma"
    EXTENSION = "lzma"

    def __init__(self):
        super().__init__(mime=Lzma.MIME, extension=Lzma.EXTENSION)

    def match(self, buf):
        return (
            len(buf) > 3
            and buf[0] == 0x5D
            and buf[1] == 0x00
            and buf[2] == 0x00
            and buf[3] == 0x00
        )


def Extractor(*args, **kwargs):
    """Provides a context which extraction is done in"""
    return TempDirExtractorContext(*args, **kwargs)
