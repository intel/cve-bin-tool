# Copyright (C) 2023 Anthony Harrison
# SPDX-License-Identifier: Apache-2.0

import string

from lib4sbom.license import LicenseScanner


class SBOMFile:
    def __init__(self):
        self.file = {}
        self.license = LicenseScanner()

    def _text(self, text_item):
        return text_item.replace("<text>", "").replace("</text>", "")

    def initialise(self):
        self.file = {}
        # Set defaults for mandatory items
        self.set_name("TBD")
        self.set_id("NOT_DEFINED")

    def set_name(self, name):
        self.file["name"] = name

    def set_id(self, id):
        self.file["id"] = id

    def set_filetype(self, type):
        file_type = type.upper()
        if file_type not in [
            "SOURCE",
            "BINARY",
            "ARCHIVE",
            "APPLICATION",
            "AUDIO",
            "IMAGE",
            "TEXT",
            "VIDEO",
            "DOCUMENTATION",
            "SPDX",
            "OTHER",
        ]:
            file_type = "OTHER"
        if "filetype" in self.file:
            self.file["filetype"].append(file_type)
        else:
            self.file["filetype"] = [file_type]

    def set_checksum(self, type, value):
        # Only store valid checksums
        if self._valid_checksum(value):
            # Allow multiple entries
            checksum_entry = [type.strip(), value.lower()]
            if "checksum" in self.file:
                self.file["checksum"].append(checksum_entry)
            else:
                self.file["checksum"] = [checksum_entry]

    def set_licenseconcluded(self, license):
        self.file["licenseconcluded"] = license

    def set_licenseinfoinfile(self, license_info):
        # Validate license
        license_id = self.license.find_license(license_info)
        # Only include if valid license
        if "licenseinfoinfile" in self.file:
            self.file["licenseinfoinfile"].append(license_id)
        else:
            self.file["licenseinfoinfile"] = [license_id]

    def set_licensecomment(self, comment):
        self.file["licensecomment"] = self._text(comment)

    def set_copyrighttext(self, text):
        self.file["copyrighttext"] = self._text(text)

    def set_comment(self, comment):
        self.file["comment"] = self._text(comment)

    def set_notice(self, notice):
        self.file["notice"] = self._text(notice)

    def set_contributor(self, name):
        if len(name) > 0:
            # Allow multiple entries
            if "contributor" in self.file:
                self.file["contributor"].append(name)
            else:
                self.file["contributor"] = [name]

    def set_attribution(self, attribution):
        self.file["attribution"] = attribution

    def set_value(self, key, value):
        self.file[key] = value

    def get_file(self):
        return self.file

    def get_name(self):
        return self.get_value("name")

    def get_value(self, attribute):
        return self.file.get(attribute, None)

    def debug_file(self):
        print("OUTPUT:", self.file)

    def show_file(self):
        for key in self.file:
            print(f"{key}    : {self.file[key]}")

    def copy_file(self, file_info):
        for key in file_info:
            self.set_value(key, file_info[key])

    def _valid_checksum(self, value):
        # Checksum length is either 32, 40, 64, 96 or 128 characters
        if len(value) not in [32, 40, 64, 96, 128]:
            return False
        # Only allow valid hex or decimal digits
        return all(c in string.hexdigits for c in value.lower())
