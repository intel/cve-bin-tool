# Copyright (C) 2023 Anthony Harrison
# SPDX-License-Identifier: Apache-2.0


class SBOMRelationship:
    def __init__(self):
        self.relationship = {}

    def initialise(self):
        self.relationship = {}

    def set_relationship(self, source, type, target):
        self.relationship["source"] = source
        self.relationship["type"] = type.strip()
        self.relationship["target"] = target
        self.relationship["source_id"] = None
        self.relationship["target_id"] = None

    def set_relationship_id(self, id_s, id_t):
        self.relationship["source_id"] = id_s
        self.relationship["target_id"] = id_t

    def set_source_type(self, source_type):
        self.relationship["source_type"] = source_type

    def set_target_type(self, target_type):
        self.relationship["target_type"] = target_type

    def get_relationship(self):
        return self.relationship

    def get_source(self):
        return self.relationship["source"]

    def get_type(self):
        return self.relationship["type"]

    def get_target(self):
        return self.relationship["target"]

    def get_source_type(self):
        return self.relationship.get("source_type", None)

    def get_target_type(self):
        return self.relationship.get("target_type", None)

    def show_relationship(self):
        for key in self.relationship:
            print(f"{key}    : {self.relationship[key]}")

    def debug_relationship(self):
        print("OUTPUT:", self.relationship)
