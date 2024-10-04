# Copyright (C) 2024 Anthony Harrison
# SPDX-License-Identifier: Apache-2.0

import re


class ModelDataset:
    def __init__(self):
        self.dataset = {}

    def set_data(self, dataref):
        ref_pattern = "^urn:cdx:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/[1-9][0-9]*#.+$"
        check_pattern = re.match(ref_pattern, dataref)
        if check_pattern is not None:
            if "data" in self.dataset:
                self.dataset["data"].append(dataref)
            else:
                self.dataset["data"] = [dataref]

    def set_name(self, name):
        self.dataset["name"] = name

    def set_id(self, id):
        self.dataset["id"] = id

    def set_dataset_type(self, type):
        dataset_type = type.upper().replace("_", "-").strip()
        if dataset_type in [
            "SOURCE-CODE",
            "CONFIGURATION",
            "DATASET",
            "DEFINITION",
            "OTHER",
        ]:
            self.dataset["dataset_type"] = dataset_type.lower()

    def set_contents(self, content="", content_type=None, url=None):
        if len(content) > 0:
            self.dataset["content"] = content
            self.dataset["encoding"] = "base64"
            if content_type is None:
                self.dataset["content_type"] = "text/plain"
            else:
                self.dataset["content_type"] = content_type
        if url is not None:
            self.dataset["url"] = url

    def set_content_property(self, name, value):
        # Allow multiple entries
        property_entry = [name.strip(), value]
        if "property" in self.dataset:
            self.dataset["property"].append(property_entry)
        else:
            self.dataset["property"] = [property_entry]

    def set_classification(self, classification):
        if len(classification) > 0:
            self.dataset["classification"] = classification

    def set_sensitive_data(self, sensitive_data):
        if len(sensitive_data) > 0:
            self.dataset["sensitive_data"] = sensitive_data

    def set_graphics(self, graphicset):
        if len(graphicset):
            self.dataset["graphics"] = graphicset

    def set_description(self, description):
        if len(description) > 0:
            self.dataset["description"] = description

    def _check_contact(self, item):
        if item.get("organization") is not None or item.get("contact") is not None:
            return True
        return False

    def set_governance(self, custodian={}, steward={}, owner={}):
        if self._check_contact(custodian):
            if "custodian" in self.dataset:
                self.dataset["custodian"].append(custodian)
            else:
                self.dataset["custodian"] = [custodian]
        if self._check_contact(steward):
            if "steward" in self.dataset:
                self.dataset["steward"].append(steward)
            else:
                self.dataset["steward"] = [steward]
        if self._check_contact(owner):
            if "owner" in self.dataset:
                self.dataset["owner"].append(owner)
            else:
                self.dataset["owner"] = [owner]

    def get_dataset(self):
        return self.dataset

    def get_value(self, attribute):
        return self.dataset.get(attribute, None)


class ModelGraphicset:
    def __init__(self):
        self.graphicset = {}

    def set_description(self, description):
        if len(description) > 0:
            self.graphicset["description"] = description

    def add_image(self, name, image):
        if "collection" in self.graphicset:
            self.graphicset["collection"].append([name, image])
        else:
            self.graphicset["collection"] = [[name, image]]

    def get_graphicset(self):
        return self.graphicset

    def get_value(self, attribute):
        return self.graphicset.get(attribute, None)


class SBOMModelCard:
    def __init__(self):
        self.modelcard = {}

    def initialise(self):
        self.modelcard = {}

    def set_name(self, name):
        self.modelcard["name"] = name

    def set_id(self, id):
        self.modelcard["id"] = id

    # Parameters

    def set_model_type(self, type):
        model_type = type.upper().replace("_", "-").strip()
        if model_type in [
            "SUPERVISED",
            "UNSUPERVISED",
            "REINFORCEMENT-LEARNING",
            "SEMI-SUPERVISED",
            "SELF-SUPERVISED",
        ]:
            self.modelcard["learning_type"] = model_type.lower()

    def set_task(self, task_description):
        if len(task_description) > 0:
            self.modelcard["task"] = task_description

    def set_architecture(self, architecture):
        if len(architecture) > 0:
            self.modelcard["architecture"] = architecture

    def set_model(self, model):
        if len(model) > 0:
            self.modelcard["model"] = model

    def set_dataset(self, dataset):
        if dataset is not None:
            if "dataset" in self.modelcard:
                self.modelcard["dataset"].append(dataset)
            else:
                self.modelcard["dataset"] = [dataset]

    def set_inputs(self, input):
        if len(input) > 0:
            if "inputs" in self.modelcard:
                self.modelcard["inputs"].append(input)
            else:
                self.modelcard["inputs"] = [input]

    def set_outputs(self, output):
        if len(output) > 0:
            if "outputs" in self.modelcard:
                self.modelcard["outputs"].append(output)
            else:
                self.modelcard["outputs"] = [output]

    def set_property(self, name, value):
        # Allow multiple entries
        property_entry = [name.strip(), value]
        if "property" in self.modelcard:
            self.modelcard["property"].append(property_entry)
        else:
            self.modelcard["property"] = [property_entry]

    def _add_stringvalue(self, attribute, value):
        if len(value) > 0:
            if attribute in self.modelcard:
                self.modelcard[attribute].append(value)
            else:
                self.modelcard[attribute] = [value]

    def set_user(self, user):
        self._add_stringvalue("user", user)

    def set_usecase(self, usecase):
        self._add_stringvalue("usecase", usecase)

    def set_limitation(self, limitation):
        self._add_stringvalue("limitation", limitation)

    def set_tradeoff(self, tradeoff):
        self._add_stringvalue("tradeoff", tradeoff)

    def set_ethicalrisk(self, risk, mitigation):
        self._add_stringvalue("ethicalrisk", [risk, mitigation])

    def set_fairness(self, risk, benefit, harm, mitigation):
        self._add_stringvalue("fairness", [risk, benefit, harm, mitigation])

    def set_graphics(self, graphicset):
        self.modelcard["graphics"] = graphicset

    def set_performance(self, type, value, slicename, lowerbound, upperbound):
        self._add_stringvalue(
            "performance", [type, value, slicename, lowerbound, upperbound]
        )

    def set_value(self, key, value):
        self.modelcard[key] = value

    def get_modelcard(self):
        return self.modelcard

    def get_value(self, attribute):
        return self.modelcard.get(attribute, None)

    def debug_modelcard(self):
        print("OUTPUT:", self.modelcard)

    def show_modelcard(self):
        for key in self.modelcard:
            print(f"{key}    : {self.modelcard[key]}")

    def copy_modelcard(self, modelcard_info):
        for key in modelcard_info:
            self.set_value(key, modelcard_info[key])

    def get_name(self):
        return self.get_value("name")
