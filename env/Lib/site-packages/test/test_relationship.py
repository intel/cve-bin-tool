import pytest

from lib4sbom.data.relationship import SBOMRelationship as test_module


class TestRelationship:
    def test_initialise(self):
        test_item = test_module()
        test_item.initialise()
        assert len(test_item.get_relationship()) == 0

    def test_set_relationship(self):
        test_item = test_module()
        test_item.set_relationship("source_module", "a_relationship", "target_module")
        assert test_item.get_relationship() == {
            "source": "source_module",
            "type": "a_relationship",
            "target": "target_module",
            "source_id": None,
            "target_id": None,
        }

    def test_get_source(self):
        test_item = test_module()
        test_item.set_relationship("source_module", "a_relationship", "target_module")
        assert test_item.get_source() == "source_module"

    def test_get_type(self):
        test_item = test_module()
        test_item.set_relationship("source_module", "a_relationship", "target_module")
        assert test_item.get_type() == "a_relationship"

    def test_get_target(self):
        test_item = test_module()
        test_item.set_relationship("source_module", "a_relationship", "target_module")
        assert test_item.get_target() == "target_module"
