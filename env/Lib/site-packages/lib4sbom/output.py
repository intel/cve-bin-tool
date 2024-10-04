# Copyright (C) 2023 Anthony Harrison
# SPDX-License-Identifier: Apache-2.0

""" Set up Output Formatting """

import json

import yaml


class _OutputManager:
    """Helper class for managing output to file and console."""

    def __init__(self, out_type="file", filename=None):
        self.out_type = out_type
        self.filename = filename
        if self.out_type == "file" and self.filename != "":
            try:
                self.file_handle = open(filename, "w", encoding="utf-8")
            except FileNotFoundError:
                # Unable to create file, so send output to console
                self.out_type = "console"
                self.file_handle = None
        else:
            self.out_type = "console"
            self.file_handle = None

    def close(self):
        if self.out_type == "file":
            self.file_handle.close()

    def file_out(self, message):
        self.file_handle.write(message + "\n")

    def console_out(self, message):
        print(message)

    def show(self, message):
        if self.out_type == "file":
            self.file_out(message)
        else:
            self.console_out(message)


class SBOMOutput:
    """Output manager for SBOM data."""

    def __init__(self, filename="", output_format="tag"):
        self.filename = filename
        self.output_format = output_format.lower()
        self.format_process = {
            "tag": self.format_tag_data,
            "json": self.format_json_data,
            "yaml": self.format_yaml_data,
        }
        if self.output_format not in ["tag", "json", "yaml"]:
            # Assume a default format
            self.output_format = "tag"
        self.type = "console"
        if self.filename != "":
            self.type = "file"
        self.output_manager = _OutputManager(self.type, self.filename)

    def format_json_data(self, data):
        json_data = json.dumps(data, indent=2)
        self.send_output(json_data)

    def format_yaml_data(self, data):
        yaml_data = yaml.dump(data)
        self.send_output(yaml_data)

    def format_tag_data(self, dataset):
        for data_item in dataset:
            self.send_output(data_item)

    def send_output(self, data):
        self.output_manager.show(data)

    def generate_output(self, dataset):
        self.format_process[self.output_format](dataset)
        self.output_manager.close()

    def get_format(self):
        return self.output_format

    def get_type(self):
        return self.type
