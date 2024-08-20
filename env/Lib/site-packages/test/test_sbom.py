import pytest

from lib4sbom.data.document import SBOMDocument
from lib4sbom.data.file import SBOMFile
from lib4sbom.data.package import SBOMPackage
from lib4sbom.data.relationship import SBOMRelationship
from lib4sbom.sbom import SBOM as test_module


class TestSbom:
    def _create_test_document(self):
        test_doc = SBOMDocument()
        test_doc.set_name("test_document")
        test_doc.set_type("spdx")
        test_doc.set_version("SPDX-2.3")
        return test_doc.get_document()

    def _create_test_files(self):
        test_file = SBOMFile()
        test_file.set_name("test_file")
        test_file.set_id("id001")
        test_files = {}
        test_files[test_file.get_name()] = test_file.get_file()
        test_file.initialise()
        test_file.set_name("test_file2")
        test_file.set_id("id002")
        test_file.set_filetype("SOURCE")
        test_files[test_file.get_name()] = test_file.get_file()
        return test_files

    def _create_test_packages(self):
        test_package = SBOMPackage()
        test_package.set_name("glibc")
        test_package.set_version("2.15")
        test_package.set_supplier("organisation", "gnu")
        test_package.set_licensedeclared("GPL3")
        test_packages = {}
        test_packages[
            (test_package.get_name(), test_package.get_value("version"))
        ] = test_package.get_package()
        test_package.initialise()
        test_package.set_name("glibc")
        test_package.set_version("2.29")
        test_package.set_supplier("organisation", "gnu")
        test_package.set_licensedeclared("GPL3")
        test_packages[
            (test_package.get_name(), test_package.get_value("version"))
        ] = test_package.get_package()
        test_package.initialise()
        test_package.set_name("tomcat")
        test_package.set_version("9.0.46")
        test_package.set_supplier("organisation", "apache")
        test_package.set_licensedeclared("Apache-2.0")
        test_packages[
            (test_package.get_name(), test_package.get_value("version"))
        ] = test_package.get_package()
        return test_packages

    def _create_test_relationships(self):
        test_relationship = SBOMRelationship()
        test_relationship.set_relationship(
            "source_module", "a_relationship", "target_module"
        )
        test_relationships = []
        test_relationships.append(test_relationship.get_relationship())
        test_relationship.initialise()
        test_relationship.set_relationship(
            "source_module", "another_relationship", "target_module2"
        )
        test_relationships.append(test_relationship.get_relationship())
        return test_relationships

    def test_document(self):
        test_item = test_module()
        # What happens if nothing defined?
        assert len(test_item.get_document()) == 0
        test_item.add_document(self._create_test_document())
        # Now retrieve it
        my_doc = test_item.get_document()
        # And validate data is as added
        assert my_doc["name"] == "test_document"
        assert my_doc["type"] == "spdx"
        assert my_doc["version"] == "SPDX-2.3"

    def test_files(self):
        test_item = test_module()
        # What happens if no files?
        my_files = test_item.get_files()
        assert len(my_files) == 0
        test_item.add_files(self._create_test_files())
        # Now retrieve data
        my_files = test_item.get_files()
        # And validate data is as added
        assert len(my_files) == 2
        assert my_files[0]["name"] == "test_file"
        assert my_files[1]["filetype"] == ["SOURCE"]

    def test_packages(self):
        test_item = test_module()
        # What happens if no packages?
        assert len(test_item.get_packages()) == 0
        # Add data
        test_item.add_packages(self._create_test_packages())
        # Now retrieve data
        my_packages = test_item.get_packages()
        # And validate data is as added
        assert len(my_packages) == 3
        assert my_packages[0]["version"] == "2.15"
        assert my_packages[1]["version"] == "2.29"
        assert my_packages[2]["licensedeclared"] == "Apache-2.0"

    def test_relationships(self):
        test_item = test_module()
        # Check what happens if no relationships defined
        assert len(test_item.get_relationships()) == 0
        # Add data
        test_item.add_relationships(self._create_test_relationships())
        # Now retrieve data
        my_relationships = test_item.get_relationships()
        # And validate data is as added
        assert len(my_relationships) == 2
        assert my_relationships[0]["source"] == "source_module"
        assert my_relationships[1]["target"] == "target_module2"

    def test_sbom_data(self):
        test_item = test_module()
        # Check an empty SBOM
        assert len(test_item.get_sbom()) == 1
        assert test_item.get_sbom() == {"type": "auto"}
        # Create SBOM
        test_item.add_document(self._create_test_document())
        test_item.add_files(self._create_test_files())
        test_item.add_packages(self._create_test_packages())
        test_item.add_relationships(self._create_test_relationships())
        # Check data
        my_sbom = test_item.get_sbom()
        assert my_sbom.get("document", None) != None
        assert my_sbom.get("files", None) != None
        assert my_sbom.get("packages", None) != None
        assert my_sbom.get("relationships", None) != None

    def test_set_type(self):
        test_item = test_module()
        assert test_item.get_type() == "auto"
        test_item.set_type("test_type")
        assert test_item.get_type() == "test_type"

    def test_set_version(self):
        test_item = test_module()
        assert test_item.get_version() == ""
        test_item.set_version("test_version")
        assert test_item.get_version() == "test_version"
