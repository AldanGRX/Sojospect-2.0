#This script is to obtain and parse the yaml vulnerabilities

import yaml
import os.path

def vuln_extract(cwe_id):
    with open(f'{os.path.dirname(__file__)}/Vulnerability YAML files/{cwe_id}.yaml','r') as file:
        return yaml.safe_load(file)

