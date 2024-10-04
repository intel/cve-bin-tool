# Copyright (C) 2024 Anthony Harrison
# SPDX-License-Identifier: Apache-2.0

class SBOMComposition:
    def __init__(self):
        self.composition = {}

    def initialise(self):
        self.composition = {}

    def add(self, aggregate, assembly, dependency = None):
        if aggregate in [ "complete", "incomplete", "incomplete_first_party_only", "incomplete_first_party_proprietary_only",
            "incomplete_first_party_opensource_only", "incomplete_third_party_only", "incomplete_third_party_proprietary_only",
            "incomplete_third_party_opensource_only", "unknown", "not_specified" ]:
            composition_entry = [aggregate, assembly,  dependency]
            if len (self.composition) > 0:
                self.composition.append(composition_entry)
            else:
                self.composition = [composition_entry]
                
    def get_composition(self):
        return self.composition

    def debug_composition(self):
        print("OUTPUT:", self.composition)

    def show_composition(self):
        for key in self.composition:
            print(f"{key}    : {self.composition[key]}")
