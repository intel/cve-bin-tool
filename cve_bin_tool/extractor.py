'''
Extraction of archives
'''
import os
import shutil
import tempfile
import itertools
import subprocess
from contextlib import contextmanager

from .log import LOGGER

class ExtractionFailed(ValueError):
    pass

class UnknownArchiveType(ValueError):
    pass

@contextmanager
def PopenCTX(*args, **kwargs):
    ''' Python 2 does not support context manager style Popen.'''
    proc = subprocess.Popen(*args, **kwargs)
    try:
        yield proc
    finally:
        if 'stdout' in kwargs:
            proc.stdout.close()
        proc.terminate()
        proc.wait()

class BaseExtractor(object):
    '''Extracts tar, rpm, etc. files'''

    def __init__(self, logger=None):
        '''Sets up logger and if we should extract files or just report'''
        if logger is None:
            logger = LOGGER.getChild(self.__class__.__name__)
        self.logger = logger
        self.file_extractors = {
            self.extract_file_tar: ['.tgz', '.tar.gz', '.tar', '.tar.xz', '.tar.bz2'],
            self.extract_file_rpm: ['.rpm'],
            self.extract_file_deb: ['.deb', '.ipk'],
            self.extract_file_cab: ['.cab'],
            self.extract_file_zip: ['.exe', '.zip', '.jar'],
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
        return subprocess.call(
            ["tar", "-C", extraction_path, "-axf", filename])

    @classmethod
    def extract_file_rpm(cls, filename, extraction_path):
        """ Extract rpm packages """
        with PopenCTX(["rpm2cpio", filename], stdout=subprocess.PIPE) as proc:
            return subprocess.call(["cpio", "-idmv"], stdin=proc.stdout,
                                   cwd=extraction_path)

    @classmethod
    def extract_file_deb(cls, filename, extraction_path):
        """ Extract debian packages """
        if subprocess.call(["ar", "x", filename], cwd=extraction_path) != 0:
            return 1
        for filename in os.listdir(extraction_path):
            if '.tar' in filename:
                result = subprocess.call(
                    ["tar", "-C", extraction_path, "-zxf",
                     os.path.join(extraction_path, filename)])
                os.unlink(os.path.join(extraction_path, filename))
                if result != 0:
                    return result
        return 0

    @classmethod
    def extract_file_cab(cls, filename, extraction_path):
        """ Extract cab files """
        return subprocess.call(
            ["cabextract", "-d", extraction_path, filename])

    @classmethod
    def extract_file_zip(cls, filename, extraction_path):
        """ Extract zip files """
        return subprocess.call(
            ["unzip", "-qq", "-n", "-d", extraction_path, filename])

class TempDirExtractorContext(BaseExtractor):
    '''Extracts tar, rpm, etc. files'''

    def __init__(self, raise_failure = False, *args, **kwargs):
        BaseExtractor.__init__(self, *args, **kwargs)
        self.tempdir = None
        self.raise_failure = raise_failure

    def extract(self, filename):
        """ Run the extractor """
        for extractor in self.file_extractors:
            for extention in self.file_extractors[extractor]:
                if filename[::-1].startswith(extention[::-1]):
                    extracted_path = os.path.join(self.tempdir,
                                                  os.path.basename(filename) + \
                                                  ".extracted")
                    if os.path.exists(extracted_path):
                        shutil.rmtree(extracted_path)
                    os.makedirs(extracted_path)
                    if extractor(filename, extracted_path) != 0:
                        if self.raise_failure:
                            raise ExtractionFailed(filename)
                        else:
                            self.logger.warning('Failure extracting %r',
                                                filename)
                    else:
                        self.logger.debug('Extracted %r to %r', filename,
                                          extracted_path)
                    return extracted_path
        raise UnknownArchiveType(filename)

    def __enter__(self):
        ''' Create a temporary directory to extract files to. '''
        self.tempdir = tempfile.mkdtemp()
        return self

    def __exit__(self, exc_type, exc, exc_tb):
        """ Removes all extraction directories that need to be cleaned up."""
        shutil.rmtree(self.tempdir)

class Extractor(BaseExtractor):
    '''Provides a context which extraction is done in'''

    def __call__(self, *args, **kwargs):
        return TempDirExtractorContext(*args, **kwargs)
