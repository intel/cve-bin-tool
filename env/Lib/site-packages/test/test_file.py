import pytest

from lib4sbom.data.file import SBOMFile as test_module


class TestFile:
    def test_initialise(self):
        test_item = test_module()
        test_item.initialise()
        assert len(test_item.get_file()) == 2

    def test_set_name(self):
        test_item = test_module()
        test_item.set_name("test_name")
        assert test_item.get_value("name") == "test_name"

    def test_set_id(self):
        test_item = test_module()
        test_item.set_id("test_id")
        assert test_item.get_value("id") == "test_id"

    def test_set_filetype(self):
        test_item = test_module()
        test_item.set_filetype("font")
        # If not valid filetype, default to OTHER
        assert test_item.get_value("filetype") == ["OTHER"]
        test_item.set_filetype("Source")
        # Filetype is always uppercase
        assert test_item.get_value("filetype") == ["OTHER", "SOURCE"]

    def test_set_checksum(self):
        test_item = test_module()
        test_item.set_checksum("sha1", "03AB567890de")
        # This in an invalid checksum value
        test_item.set_checksum("sha1", "invalid_sum")
        # All checkums are stored as lower case
        assert test_item.get_value("checksum") == [["sha1", "03ab567890de"]]

    def test_set_licenseconcluded(self):
        test_item = test_module()
        test_item.set_licenseconcluded("test_licenseconcluded")
        assert test_item.get_value("licenseconcluded") == "test_licenseconcluded"

    def test_set_licenseinfoinfile(self):
        test_item = test_module()
        test_item.set_licenseinfoinfile("test_licenseinfoinfile")
        # Invalid license
        assert test_item.get_value("licenseinfoinfile") == ["NOASSERTION"]
        test_item.set_licenseinfoinfile("MIT")
        assert test_item.get_value("licenseinfoinfile") == ["NOASSERTION", "MIT"]

    def test_set_licensecomment(self):
        test_item = test_module()
        test_item.set_licensecomment("test_licensecomment")
        assert test_item.get_value("licensecomment") == "test_licensecomment"

    def test_set_copyrighttext(self):
        test_item = test_module()
        test_item.set_copyrighttext("test_copyrighttext")
        assert test_item.get_value("copyrighttext") == "test_copyrighttext"

    def test_set_comment(self):
        test_item = test_module()
        test_item.set_comment("test_comment")
        assert test_item.get_value("comment") == "test_comment"

    def test_set_notice(self):
        test_item = test_module()
        test_item.set_notice("test_notice")
        assert test_item.get_value("notice") == "test_notice"

    def test_set_contributor(self):
        test_item = test_module()
        test_item.set_contributor("test_contributor")
        assert test_item.get_value("contributor") == ["test_contributor"]

    def test_set_attribution(self):
        test_item = test_module()
        test_item.set_attribution("test_attribution")
        assert test_item.get_value("attribution") == "test_attribution"

    def test_set_value(self):
        test_item = test_module()
        test_item.set_value("test_value", "some test data")
        assert test_item.get_value("test_value") == "some test data"

    def test_get_file(self):
        test_item = test_module()
        test_item.set_name("test_file")
        test_item.set_id("id001")
        test_file = test_item.get_file()
        assert test_file["name"] == "test_file"
        assert test_file["id"] == "id001"

    def test_get_value(self):
        test_item = test_module()
        test_item.set_value("attribute", "a_value")
        assert test_item.get_value("attribute") == "a_value"

    def test_copy_file(self):
        test_item = test_module()
        test_item.set_name("item1")
        test_item.set_id("1234")
        test_item_copy = test_module()
        test_item_copy.copy_file(test_item.get_file())
        assert len(test_item.get_file()) == len(test_item_copy.get_file())
        assert test_item.get_name() == test_item_copy.get_name()
        assert test_item_copy.get_value("id") == "1234"

    def test_get_name(self):
        test_item = test_module()
        test_item.set_name("test_file")
        assert test_item.get_name() == "test_file"
