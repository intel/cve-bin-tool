import pytest

from lib4sbom.data.document import SBOMDocument as test_module


class TestDocument:
    def test_initialise(self):
        test_item = test_module()
        test_item.initialise()
        assert len(test_item.get_document()) == 0

    def test_set_name(self):
        test_item = test_module()
        test_item.set_name("test_name")
        assert test_item.get_value("name") == "test_name"

    def test_set_id(self):
        test_item = test_module()
        test_item.set_id("test_id")
        assert test_item.get_value("id") == "test_id"

    def test_set_version(self):
        test_item = test_module()
        test_item.set_version("test_version")
        assert test_item.get_value("version") == "test_version"

    def test_set_type(self):
        test_item = test_module()
        test_item.set_type("test_type")
        assert test_item.get_value("type") == "test_type"

    def test_set_datalicense(self):
        test_item = test_module()
        test_item.set_datalicense("test_datalicense")
        assert test_item.get_value("datalicense") == "test_datalicense"

    def test_set_created(self):
        test_item = test_module()
        test_item.set_created("2023-10-21T12:34:56Z")
        assert test_item.get_value("created") == "2023-10-21T12:34:56Z"

    def test_set_value(self):
        test_item = test_module()
        test_item.set_value("attribute", "a_value")
        assert test_item.get_value("attribute") == "a_value"

    def test_get_document(self):
        test_item = test_module()
        test_item.set_name("test_document")
        test_item.set_id("id001")
        test_document = test_item.get_document()
        assert test_document["name"] == "test_document"
        assert test_document["id"] == "id001"

    def test_copy_document(self):
        test_item = test_module()
        test_item.set_name("item1")
        test_item.set_id("1234")
        test_item_copy = test_module()
        test_item_copy.copy_document(test_item.get_document())
        assert len(test_item.get_document()) == len(test_item_copy.get_document())
        assert test_item.get_name() == test_item_copy.get_name()
        assert test_item_copy.get_value("id") == "1234"

    def test_get_name(self):
        test_item = test_module()
        test_item.set_name("test_name")
        assert test_item.get_name() == "test_name"

    def test_get_version(self):
        test_item = test_module()
        test_item.set_version("test_version")
        assert test_item.get_version() == "test_version"

    def test_get_type(self):
        test_item = test_module()
        test_item.set_type("test_type")
        assert test_item.get_type() == "test_type"

    def test_get_datalicense(self):
        test_item = test_module()
        test_item.set_datalicense("test_datalicense")
        assert test_item.get_datalicense() == "test_datalicense"

    def test_get_created(self):
        test_item = test_module()
        test_item.set_created("2023-10-21T12:34:56Z")
        assert test_item.get_created() == "2023-10-21T12:34:56Z"

    def test_get_value(self):
        test_item = test_module()
        test_item.set_value("attribute", "a_value")
        assert test_item.get_value("attribute") == "a_value"

    def test_show_document(self):
        test_item = test_module()
        test_item.set_name("item1")
        test_item.set_id("1234")
        test_item.show_document()
