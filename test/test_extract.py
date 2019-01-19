import os
import sys
import shutil
import tarfile
import tempfile
import unittest
from zipfile import ZipFile, ZipInfo
from io import BytesIO
if sys.version_info.major == 3 and sys.version_info.minor >= 3:
    import lzma

from cve_bin_tool.extractor import Extractor

from .test_definitions import download_file, \
                              CURL_7_20_0_URL, \
                              VMWARE_CAB, \
                              TMUX_DEB

# Enable logging if tests are not passing to help you find errors
# import logging
# logging.basicConfig(level=logging.DEBUG)

class TestExtractorBase(unittest.TestCase):
    '''Test methods for extraction of various file types'''

    @classmethod
    def setUpClass(cls):
        cls.extractor = Extractor()
        cls.tempdir = tempfile.mkdtemp(prefix='cve-bin-tool-')

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tempdir)

    def extract_files(self, filenames):
        # Make sure all test files are present
        for filename in filenames:
            self.assertTrue(os.path.exists(os.path.join(self.tempdir, filename)),
                            'test file %r was not found' % (filename,))
        # Make sure extraction reports success
        for filename in filenames:
            with self.extractor() as ectx:
                yield ectx.extract(os.path.join(self.tempdir, filename))

class TestExtractor(TestExtractorBase):

    def test_can_extract(self):
        self.assertTrue(self.extractor.can_extract('.tar.bz2'))
        self.assertTrue(self.extractor.can_extract('.zip'))
        self.assertTrue(self.extractor.can_extract('.deb'))

class TestExtractFileTar(TestExtractorBase):

    def setUp(self):
        for filename, tarmode in [('test.tgz', 'w:gz'),
                                  ('test.tar.gz', 'w:gz'),
                                  ('test.tar.bz2', 'w:bz2'),
                                  ('test.tar', 'w')]:
            tarpath = os.path.join(self.tempdir, filename)
            tar = tarfile.open(tarpath, mode=tarmode)
            data = 'feedface'.encode('utf-8')
            addfile = BytesIO(data)
            info = tarfile.TarInfo(name='test.txt')
            info.size = len(data)
            tar.addfile(tarinfo=info, fileobj=addfile)
            tar.close()
        if sys.version_info.major == 3 and sys.version_info.minor >= 3:
            tarpath = os.path.join(self.tempdir, 'test.tar')
            tarpath_xz = os.path.join(self.tempdir, 'test.tar.xz')
            with open(tarpath, 'rb') as infile, \
                    lzma.open(tarpath_xz , 'w') as outfile:
                outfile.write(infile.read())

    def test_extract_file_tar(self):
        try:
            self.extract_files(['test' + e for e in
                self.extractor.file_extractors[self.extractor.extract_file_tar]])
        except AssertionError as error:
            # Don't if we failed the xz test on versions were we couldn't create
            # the file
            if sys.version_info.major == 3 and sys.version_info.minor >= 3:
                raise

    def test_extract_cleanup(self):
        with self.extractor() as ectx:
            extracted_path = ectx.extract(os.path.join(self.tempdir,
                                                       'test.tar'))
            self.assertTrue(os.path.isdir(extracted_path))
        self.assertFalse(os.path.exists(extracted_path))

class TestExtractFileRpm(TestExtractorBase):

    def setUp(self):
        download_file(CURL_7_20_0_URL, os.path.join(self.tempdir, 'test.rpm'))

    def test_extract_file_rpm(self):
        for extracted_path in self.extract_files(['test' + e for e in
                self.extractor.file_extractors[self.extractor.extract_file_rpm]]):
            self.assertTrue(os.path.isfile(os.path.join(extracted_path, 'usr',
                                                        'bin', 'curl')))

class TestExtractFileDeb(TestExtractorBase):

    def setUp(self):
        download_file(TMUX_DEB, os.path.join(self.tempdir, 'test.deb'))
        shutil.copyfile(os.path.join(self.tempdir, 'test.deb'),
                        os.path.join(self.tempdir, 'test.ipk'))

    def test_extract_file_deb(self):
        for extracted_path in self.extract_files(['test' + e for e in
                self.extractor.file_extractors[self.extractor.extract_file_deb]]):
            self.assertTrue(os.path.isfile(os.path.join(extracted_path, 'usr',
                                                        'bin', 'tmux')))

class TestExtractFileCab(TestExtractorBase):

    def setUp(self):
        download_file(VMWARE_CAB, os.path.join(self.tempdir, 'test.cab'))

    def test_extract_file_cab(self):
        for extracted_path in self.extract_files(['test' + e for e in
                self.extractor.file_extractors[self.extractor.extract_file_cab]]):
            self.assertTrue(os.path.isfile(os.path.join(extracted_path,
                                                        'vmware.htm')))

class TestExtractFileZip(TestExtractorBase):

    def setUp(self):
        for filename in ['test.exe', 'test.zip', 'test.jar']:
            zippath = os.path.join(self.tempdir, filename)
            with ZipFile(zippath, 'w') as zipfile:
                zipfile.writestr(ZipInfo('test.txt'), 'feedface')

    def test_extract_file_zip(self):
        self.extract_files(['test' + e for e in
            self.extractor.file_extractors[self.extractor.extract_file_zip]])
