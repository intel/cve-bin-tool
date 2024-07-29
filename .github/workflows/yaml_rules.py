import sys

import yaml


def validate_yaml(file_path):
    """Validates mismatch_relations file with custom rules."""
    with open(file_path) as file:
        try:
            data = yaml.safe_load(file)
        except yaml.YAMLError as exc:
            print(f"Error parsing YAML file {file_path}: {exc}")
            return False

    errors = []
    required_keys = ["purls", "invalid_vendors"]

    for key in required_keys:
        if key not in data or not isinstance(data[key], list):
            errors.append(f"Key '{key}' is missing or not a list in {file_path}")

    if errors:
        for error in errors:
            print(error)
        return False
    else:
        print(f"{file_path} is valid.")
        return True


if __name__ == "__main__":
    files = sys.argv[1:]
    all_valid = True

    for file in files:
        if not validate_yaml(file):
            all_valid = False

    if not all_valid:
        sys.exit(1)
