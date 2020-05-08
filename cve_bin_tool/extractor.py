# pylint: disable=useless-object-inheritance, keyword-arg-before-vararg
# disabled for python2 compatibility reasons
"""
Extraction of archives
"""
import glob
import itertools
import os
import shutil
import subprocess
import sys
import tempfile
from contextlib import contextmanager

from cve_bin_tool.log import LOGGER
from cve_bin_tool.util import inpath


class ExtractionFailed(ValueError):
    """ Extraction fail """

    # pass


class UnknownArchiveType(ValueError):
    """ Unknown archive type"""

    # pass


@contextmanager
def popen_ctx(*args, **kwargs):
    """ Python 2 does not support context manager style Popen."""
    proc = subprocess.Popen(*args, **kwargs)
    try:
        yield proc
    finally:
        if "stdout" in kwargs:
            proc.stdout.close()
        proc.terminate()
        proc.wait()


class BaseExtractor(object):
    """Extracts tar, rpm, etc. files"""

    def __init__(self, logger=None):
        """Sets up logger and if we should extract files or just report"""
        if logger is None:
            logger = LOGGER.getChild(self.__class__.__name__)
        self.logger = logger
        self.file_extractors = {
            self.extract_file_tar: [".tgz", ".tar.gz", ".tar", ".tar.xz", ".tar.bz2"],
            self.extract_file_rpm: [".rpm"],
            self.extract_file_deb: [".deb", ".ipk"],
            self.extract_file_cab: [".cab"],
            self.extract_file_zip: [".exe", ".zip", ".jar", ".apk"],
        }

    def can_extract(self, filename):
        """ Check if the filename is something we know how to extract """
        for extention in itertools.chain(*self.file_extractors.values()):
            if filename[::-1].startswith(extention[::-1]):
                return True
        return False

    @classmethod
    def extract_file_tar(cls, filename, extraction_path):
        """ Extract tar files """
        if not inpath("tar"):
            """ Acutally MinGW provides tar, so this might never get called """
            shutil.unpack_archive(filename, extraction_path)
        else:
            return subprocess.call(["tar", "-C", extraction_path, "-xf", filename])

    @classmethod
    def extract_file_rpm(cls, filename, extraction_path):
        """ Extract rpm packages """
        if sys.platform.startswith("linux"):
            if not inpath("rpm2cpio") or not inpath("cpio"):
                raise Exception(
                    "'rpm2cpio' and 'cpio' are required to extract rpm files"
                )
            else:
                with popen_ctx(["rpm2cpio", filename], stdout=subprocess.PIPE) as proc:
                    return subprocess.call(
                        ["cpio", "-idmv"], stdin=proc.stdout, cwd=extraction_path
                    )
        else:
            if not inpath("7z"):
                raise Exception("7z is required to extract rpm files")
            else:
                cpio_path = filename.split("\\")
                cpio_path = "\\".join(cpio_path[: len(cpio_path) - 1])
                subprocess.call(f'7z x {filename} -o"{cpio_path}"')

                for file in os.listdir(cpio_path):
                    if "cpio" in file:
                        filename = cpio_path + "\\" + file

                subprocess.call(f'7z x {filename} -o"{extraction_path}"')
                if os.path.isfile(filename):
                    os.remove(filename)

    @classmethod
    def extract_file_deb(cls, filename, extraction_path):
        """ Extract debian packages """
        if not inpath("ar"):
            raise Exception("'ar' is required to extract deb files")
        else:
            result = subprocess.call(["ar", "x", filename], cwd=extraction_path)
            if result != 0:
                return result
            if not inpath("tar"):
                shutil.unpack_archive(filename, extraction_path)
            else:
                datafile = glob.glob(os.path.join(extraction_path, "data.tar.*"))[0]
                # flag a is not supported while using x
                result = subprocess.call(
                    ["tar", "-C", extraction_path, "-xf", datafile]
                )
                return result

    @classmethod
    def extract_file_cab(cls, filename, extraction_path):
        """ Extract cab files """
        if sys.platform.startswith("linux"):
            if not inpath("cabextract"):
                raise Exception("'cabextract' is required to extract cab files")
            else:
                return subprocess.call(["cabextract", "-d", extraction_path, filename])
        else:
            subprocess.call(["Expand", filename, "-F:*", extraction_path])

    @classmethod
    def extract_file_zip(cls, filename, extraction_path):
        """ Extract zip files """
        if not inpath("unzip"):
            shutil.unpack_archive(filename, extraction_path)
        else:
            return subprocess.call(
                ["unzip", "-qq", "-n", "-d", extraction_path, filename]
            )


class TempDirExtractorContext(BaseExtractor):
    """Extracts tar, rpm, etc. files"""

    def __init__(self, raise_failure=False, *args, **kwargs):
        BaseExtractor.__init__(self, *args, **kwargs)
        self.tempdir = None
        self.raise_failure = raise_failure

    def extract(self, filename):
        """ Run the extractor """
        # Resolve path in case of cwd change
        filename = os.path.abspath(filename)
        for extractor in self.file_extractors:
            for extention in self.file_extractors[extractor]:
                if filename[::-1].startswith(extention[::-1]):
                    extracted_path = os.path.join(
                        self.tempdir, f"{os.path.basename(filename)}.extracted"
                    )
                    if os.path.exists(extracted_path):
                        shutil.rmtree(extracted_path)
                    os.makedirs(extracted_path, 0o700)
                    print(filename, extracted_path)
                    if extractor(filename, extracted_path) != 0:
                        if self.raise_failure:
                            raise ExtractionFailed(filename)
                        else:
                            self.logger.warning(f"Failure extracting {filename}")
                    else:
                        self.logger.debug(f"Extracted {filename} to {extracted_path}")
                    return extracted_path
        raise UnknownArchiveType(filename)

    def __enter__(self):
        """ Create a temporary directory to extract files to. """
        self.tempdir = tempfile.mkdtemp(prefix="cve-bin-tool-")
        return self

    def __exit__(self, exc_type, exc, exc_tb):
        """ Removes all extraction directories that need to be cleaned up."""
        shutil.rmtree(self.tempdir)


class Extractor(BaseExtractor):
    """Provides a context which extraction is done in"""

    def __call__(self, *args, **kwargs):
        return TempDirExtractorContext(*args, **kwargs)
