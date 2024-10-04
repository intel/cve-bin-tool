# Copyright (C) 2024 Anthony Harrison
# SPDX-License-Identifier: Apache-2.0

class SBOMLicense:
    def __init__(self):
        self.license = {}

    def _text(self, text_item):
        return text_item.replace("<text>", "").replace("</text>", "")

    def initialise(self):
        self.license = {}

    def set_name(self, name):
        self.license["name"] = name

    def set_id(self, id):
        self.license["id"] = id

    def set_value(self, key, value):
        self.license[key] = value

    def get_license(self):
        return self.license

    def get_value(self, attribute):
        return self.license.get(attribute, None)

    def debug_license(self):
        print("OUTPUT:", self.license)

    def show_license(self):
        for key in self.license:
            print(f"{key}    : {self.license[key]}")

    def copy_license(self, license_info):
        for key in license_info:
            self.set_value(key, license_info[key])

    def get_name(self):
        return self.get_value("name")

    def get_id(self):
        return self.get_value("id")

