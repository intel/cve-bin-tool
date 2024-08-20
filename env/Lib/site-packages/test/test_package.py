import pytest

from lib4sbom.data.package import SBOMPackage as test_module


class TestPackage:
    def test_initialise(self):
        test_item = test_module()
        test_item.initialise()
        assert len(test_item.get_package()) == 0

    def test_set_name(self):
        test_item = test_module()
        test_item.set_name("test_name")
        assert test_item.get_value("name") == "test_name"

    def test_set_id(self):
        test_item = test_module()
        test_item.set_id("test_id")
        assert test_item.get_value("id") == "test_id"

    def test_set_type(self):
        test_item = test_module()
        test_item.set_type("test_type")
        assert test_item.get_value("type") == "test_type"

    def test_set_version(self):
        test_item = test_module()
        test_item.set_version("test_version")
        assert test_item.get_value("version") == "test_version"

    def test_set_supplier(self):
        test_item = test_module()
        test_item.set_supplier("person", "test_supplier")
        assert test_item.get_value("supplier_type") == "person"
        assert test_item.get_value("supplier") == "test_supplier"

    def test_set_originator(self):
        test_item = test_module()
        test_item.set_originator("organisation", "test_originator")
        assert test_item.get_value("originator_type") == "organisation"
        assert test_item.get_value("originator") == "test_originator"

    def test_set_downloadlocation(self):
        test_item = test_module()
        test_item.set_downloadlocation("test_downloadlocation")
        assert test_item.get_value("downloadlocation") == "test_downloadlocation"

    def test_set_filename(self):
        test_item = test_module()
        test_item.set_filename("test_filename")
        assert test_item.get_value("filename") == "test_filename"

    def test_set_homepage(self):
        test_item = test_module()
        test_item.set_homepage("test_homepage")
        assert test_item.get_value("homepage") == "test_homepage"

    def test_set_sourceinfo(self):
        test_item = test_module()
        test_item.set_sourceinfo("test_sourceinfo")
        assert test_item.get_value("sourceinfo") == "test_sourceinfo"

    def test_set_filesanalysis(self):
        test_item = test_module()
        test_item.set_filesanalysis("test_filesanalysis")
        assert test_item.get_value("filesanalysis") == "test_filesanalysis"

    def test_set_checksum(self):
        test_item = test_module()
        test_item.set_checksum("sha512", "ab345c32a")
        assert test_item.get_value("checksum") == [["sha512", "ab345c32a"]]

    def test_set_checksum_multiple(self):
        test_item = test_module()
        test_item.set_checksum("sha128", "test_1234")
        test_item.set_checksum("alg256", "TEST_ABC123")
        test_checksum = test_item.get_value("checksum")
        assert test_checksum == None
        test_item.set_checksum("sha128", "cd45670BE")
        test_item.set_checksum("alg256", "23451deac1239870e")
        test_checksum = test_item.get_value("checksum")
        assert len(test_checksum) == 2
        assert test_checksum[0] == ["sha128", "cd45670be"]
        assert test_checksum[1] == ["alg256", "23451deac1239870e"]

    def test_set_property(self):
        test_item = test_module()
        test_item.set_property("myprop", "test_property")
        assert test_item.get_value("property") == [["myprop", "test_property"]]

    def test_set_licenseconcluded(self):
        test_item = test_module()
        test_item.set_licenseconcluded("test_licenseconcluded")
        assert test_item.get_value("licenseconcluded") == "test_licenseconcluded"

    def test_set_licensedeclared(self):
        test_item = test_module()
        test_item.set_licensedeclared("test_licensedeclared")
        assert test_item.get_value("licensedeclared") == "test_licensedeclared"

    def test_set_licensecomments(self):
        test_item = test_module()
        test_item.set_licensecomments("test_licensecomments")
        assert test_item.get_value("licensecomments") == "test_licensecomments"

    def test_set_licenseinfoinfiles(self):
        test_item = test_module()
        test_item.set_licenseinfoinfiles("test_licenseinfoinfiles")
        assert test_item.get_value("licenseinfoinfiles") == "test_licenseinfoinfiles"

    def test_set_externalreference(self):
        test_item = test_module()
        test_item.set_externalreference("category", "type", "test_externalreference")
        assert test_item.get_value("externalreference") == [
            ["category", "type", "test_externalreference"]
        ]

    def test_set_externalreference_multiple(self):
        test_item = test_module()
        test_item.set_externalreference(
            "category1", "type_1", "test_externalreference01"
        )
        test_item.set_externalreference("category2", "type2", "test_externalreference2")
        test_externalreference = test_item.get_value("externalreference")
        assert len(test_externalreference) == 2
        assert test_externalreference[0] == [
            "category1",
            "type_1",
            "test_externalreference01",
        ]
        assert test_externalreference[1] == [
            "category2",
            "type2",
            "test_externalreference2",
        ]

    def test_set_copyrighttext(self):
        test_item = test_module()
        test_item.set_copyrighttext("test_copyrighttext")
        assert test_item.get_value("copyrighttext") == "test_copyrighttext"

    def test_set_comment(self):
        test_item = test_module()
        test_item.set_comment("test_comment")
        assert test_item.get_value("comment") == "test_comment"

    def test_set_summary(self):
        test_item = test_module()
        test_item.set_summary("test_summary")
        assert test_item.get_value("summary") == "test_summary"

    def test_set_description(self):
        test_item = test_module()
        test_item.set_description("test_description")
        assert test_item.get_value("description") == "test_description"

    def test_set_value(self):
        test_item = test_module()
        test_item.set_value("value", "test_value")
        assert test_item.get_value("value") == "test_value"

    def test_get_package(self):
        test_item = test_module()
        test_item.set_name("test_package")
        test_item.set_id("id001")
        test_package = test_item.get_package()
        assert test_package["name"] == "test_package"
        assert test_package["id"] == "id001"

    def test_get_value(self):
        test_item = test_module()
        test_item.set_value("attribute", "a_value")
        assert test_item.get_value("attribute") == "a_value"

    def test_get_value_missing(self):
        test_item = test_module()
        assert test_item.get_value("attribute2") == None

    def test_copy_package(self):
        test_item = test_module()
        test_item.set_name("item1")
        test_item.set_id("1234")
        test_item_copy = test_module()
        test_item_copy.copy_package(test_item.get_package())
        assert len(test_item.get_package()) == len(test_item_copy.get_package())
        assert test_item.get_name() == test_item_copy.get_name()
        assert test_item_copy.get_value("id") == "1234"

    def test_get_name(self):
        test_item = test_module()
        test_item.set_name("test_package")
        assert test_item.get_name() == "test_package"
