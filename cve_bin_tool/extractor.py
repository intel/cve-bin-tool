# pylint: disable=useless-object-inheritance, keyword-arg-before-vararg
# disabled for python2 compatibility reasons
"""
Extraction of archives
"""
import itertools
import os
import shutil
import sys
import tempfile

from .async_utils import (
    aio_unpack_archive,
    aio_run_command,
    aio_glob,
    aio_inpath,
    aio_rmdir,
    aio_makedirs,
    aio_mkdtemp,
    ChangeDirContext,
    FileIO,
    run_coroutine,
)
from .error_handler import ExtractionFailed, UnknownArchiveType, ErrorHandler, ErrorMode
from .log import LOGGER


class BaseExtractor:
    """Extracts tar, rpm, etc. files"""

    def __init__(self, logger=None, error_mode=ErrorMode.TruncTrace):
        # Sets up logger and if we should extract files or just report
        self.logger = logger or LOGGER.getChild(self.__class__.__name__)
        self.error_mode = error_mode
        self.file_extractors = {
            self.extract_file_tar: {".tgz", ".tar.gz", ".tar", ".tar.xz", ".tar.bz2"},
            self.extract_file_rpm: {".rpm"},
            self.extract_file_deb: {".deb", ".ipk"},
            self.extract_file_cab: {".cab"},
            self.extract_file_zip: {
                ".exe",
                ".zip",
                ".jar",
                ".apk",
                ".msi",
                ".egg",
                ".whl",
            },
        }

    def can_extract(self, filename):
        """ Check if the filename is something we know how to extract """
        for extension in itertools.chain(*self.file_extractors.values()):
            if filename.endswith(extension):
                return True
        return False

    @staticmethod
    async def extract_file_tar(filename, extraction_path):
        """ Extract tar files """
        with ErrorHandler(mode=ErrorMode.Ignore) as e:
            await aio_unpack_archive(filename, extraction_path)
        return e.exit_code

    async def extract_file_rpm(self, filename, extraction_path):
        """ Extract rpm packages """
        if sys.platform.startswith("linux"):
            if not await aio_inpath("rpm2cpio") or not await aio_inpath("cpio"):
                with ErrorHandler(mode=self.error_mode, logger=self.logger):
                    raise Exception(
                        "'rpm2cpio' and 'cpio' are required to extract rpm files"
                    )
            else:
                stdout, stderr = await aio_run_command(["rpm2cpio", filename])
                if stderr or not stdout:
                    return 1
                cpio_path = os.path.join(extraction_path, "data.cpio")
                async with FileIO(cpio_path, "wb") as f:
                    await f.write(stdout)
                stdout, stderr = await aio_run_command(
                    ["cpio", "-idm", "--file", cpio_path]
                )
                if stdout or not stderr:
                    return 1
        else:
            if not await aio_inpath("7z"):
                with ErrorHandler(mode=self.error_mode, logger=self.logger):
                    raise Exception("7z is required to extract rpm files")
            else:
                stdout, stderr = await aio_run_command(["7z", "x", filename])
                if stderr or not stdout:
                    return 1
                filenames = await aio_glob(os.path.join(extraction_path, "*.cpio"))
                filename = filenames[0]

                stdout, stderr = await aio_run_command(["7z", "x", filename])
                if stderr or not stdout:
                    return 1
        return 0

    async def extract_file_deb(self, filename, extraction_path):
        """ Extract debian packages """
        if not await aio_inpath("ar"):
            with ErrorHandler(mode=self.error_mode, logger=self.logger):
                raise Exception("'ar' is required to extract deb files")
        else:
            stdout, stderr = await aio_run_command(["ar", "x", filename])
            if stderr:
                return 1
            datafile = await aio_glob(os.path.join(extraction_path, "data.tar.*"))
            with ErrorHandler(mode=ErrorMode.Ignore) as e:
                await aio_unpack_archive(datafile[0], extraction_path)
            return e.exit_code

    @staticmethod
    async def extract_file_cab(filename, extraction_path):
        """ Extract cab files """
        if sys.platform.startswith("linux"):
            if not await aio_inpath("cabextract"):
                raise Exception("'cabextract' is required to extract cab files")
            else:
                stdout, stderr = await aio_run_command(
                    ["cabextract", "-d", extraction_path, filename]
                )
                if stderr or not stdout:
                    return 1
        else:
            stdout, stderr = await aio_run_command(
                ["Expand", filename, "-F:*", extraction_path]
            )
            if stderr or not stdout:
                return 1
        return 0

    @staticmethod
    async def extract_file_zip(filename, extraction_path):
        """ Extract zip files """
        if await aio_inpath("unzip"):
            stdout, stderr = await aio_run_command(
                ["unzip", "-n", "-d", extraction_path, filename]
            )
            if stderr or not stdout:
                return 1
        elif await aio_inpath("7z"):
            stdout, stderr = await aio_run_command(["7z", "x", filename])
            if stderr or not stdout:
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
        self.tempdir = None
        self.raise_failure = raise_failure

    async def aio_extract(self, filename):
        """ Run the extractor """
        # Resolve path in case of cwd change
        filename = os.path.abspath(filename)
        for extractor in self.file_extractors:
            for extension in self.file_extractors[extractor]:
                if filename.endswith(extension):
                    extracted_path = os.path.join(
                        self.tempdir, f"{os.path.basename(filename)}.extracted"
                    )
                    if os.path.exists(extracted_path):
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
        with ErrorHandler(mode=self.error_mode, logger=self.logger):
            raise UnknownArchiveType(filename)

    async def __aenter__(self):
        """ Create a temporary directory to extract files to. """
        self.tempdir = await aio_mkdtemp(prefix="cve-bin-tool-")
        return self

    async def __aexit__(self, exc_type, exc, exc_tb):
        """ Removes all extraction directories that need to be cleaned up."""
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


def Extractor(*args, **kwargs):
    """Provides a context which extraction is done in"""
    return TempDirExtractorContext(*args, **kwargs)
