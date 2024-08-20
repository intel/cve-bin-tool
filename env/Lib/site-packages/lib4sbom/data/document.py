# Copyright (C) 2023 Anthony Harrison
# SPDX-License-Identifier: Apache-2.0


class SBOMDocument:
    def __init__(self):
        self.document = {}

    def __len__(self):
        return len(self.document)

    def initialise(self):
        self.document = {}

    def set_name(self, name):
        self.document["name"] = name

    def set_id(self, id):
        self.document["id"] = id

    def set_version(self, version):
        self.document["version"] = version

    def set_type(self, type):
        self.document["type"] = type

    def set_datalicense(self, license):
        self.document["datalicense"] = license

    def set_licenselist(self, license):
        self.document["licenselist"] = license

    def set_created(self, created):
        self.document["created"] = created

    def set_creator(self, type, creator):
        # Allow multiple entries
        creator_entry = [type.strip(), creator]
        if "creator" in self.document:
            self.document["creator"].append(creator_entry)
        else:
            self.document["creator"] = [creator_entry]

    def set_metadata_type(self, type):
        component_type = type.upper().replace("_", "-").strip()
        # Subset of SPDX and CycloneDX types/purpose
        if component_type in [
            "APPLICATION",
            "FRAMEWORK",
            "LIBRARY",
            "CONTAINER",
            "OPERATING-SYSTEM",
            "DEVICE",
            "FIRMWARE",
            "FILE",
        ]:
            self.document["metadata_type"] = component_type.lower()

    def set_metadata_supplier(self, supplier):
        self.set_value("metadata_supplier", supplier)

    def set_metadata_version(self, version):
        self.set_value("metadata_version", version)

    def set_value(self, key, value):
        self.document[key] = value

    def get_document(self):
        return self.document

    def debug_document(self):
        print("OUTPUT:", self.document)

    def show_document(self):
        for key in self.document:
            print(f"{key}    : {self.document[key]}")

    def copy_document(self, document):
        for key in document:
            self.set_value(key, document[key])

    def get_name(self):
        return self.get_value("name", default="NOT DEFINED")

    def get_version(self):
        return self.get_value("version", default="MISSING")

    def get_type(self):
        return self.get_value("type")

    def get_datalicense(self):
        return self.get_value("datalicense")

    def get_created(self):
        return self.get_value("created")

    def get_creator(self):
        return self.get_value("creator", default=[])

    def get_value(self, attribute, default=None):
        return self.document.get(attribute, default)
