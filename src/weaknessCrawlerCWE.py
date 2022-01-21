# Software is free software released under the "GNU General Public License v3.0"
# Copyright (c) 2022 Yuning-Jiang - yuning.jiang17@gmail.com

import os, sys, inspect
from xml.sax import make_parser
from xml.sax.handler import ContentHandler
import argparse
import logging
import pandas as pd
import warnings
import config

logging.getLogger('matplotlib.font_manager').disabled = True
warnings.filterwarnings("ignore")
current_dir = os.path.dirname(os.path.abspath(inspect.getfile(inspect.currentframe())))
parent_dir = os.path.dirname(current_dir)
sys.path.insert(0, parent_dir)
argparser = argparse.ArgumentParser(description='generate CWE database')
argparser.add_argument('-v', action='store_true', help='verbose output')
argparser.add_argument('-f', action='store_true', help='force update')
args = argparser.parse_args()

# Create a class to handle CWE tree structure.
class CWEHandler(ContentHandler):
    def __init__(self):
        self.cwe = []
        self.description_tag = False
        self.extend_description_tag = False
        self.category_tag = False
        self.weakness_tag = False
        self.weakness_relationships_tag = False
        self.category_relationships_tag = False

        self.potential_mitigations = False
        self.observed_examples = False
        self.detection_methods = False
        self.alternate_terms = False

    def startElement(self, name, attrs):

        if name == "Weakness":
            self.weakness_tag = True
            self.statement = ""
            self.weaknessabs = attrs.get("Abstraction")
            self.name = attrs.get("Name")
            self.idname = attrs.get("ID")
            self.status = attrs.get("Status")
            if not self.name.startswith("DEPRECATED"):
                self.cwe.append(
                    {
                        "name": self.name,
                        "id": self.idname,
                        "status": self.status,
                        "weaknessabs": self.weaknessabs,
                    }
                )

        elif name == "Category":
            self.category_tag = True
            self.category_name = attrs.get("Name")
            self.category_id = attrs.get("ID")
            self.category_status = attrs.get("Status")
            if not self.category_name.startswith("DEPRECATED"):
                self.cwe.append(
                    {
                        "name": self.category_name,
                        "id": self.category_id,
                        "status": self.category_status,
                        "weaknessabs": "Category",
                    }
                )

        elif name == "Observed_Examples":
            self.observed_examples = True

        elif name == "Potential_Mitigations":
            self.potential_mitigations = True

        elif name == "Detection_Methods":
            self.detection_methods = True

        elif name == "Alternate_Terms":
            self.alternate_terms = True

        elif (
            name == "Description"
            and self.weakness_tag
            and not self.potential_mitigations
            and not self.observed_examples
            and not self.detection_methods
            and not self.alternate_terms
        ):
            self.description_tag = True
            self.description = ""

        elif name == "Summary" and self.category_tag:
            self.description_tag = True
            self.description = ""

        elif name == "Relationships" and self.category_tag:
            self.category_relationships_tag = True
            self.relationships = []

        elif name == "Related_Weaknesses" and self.weakness_tag:
            self.weakness_relationships_tag = True
            self.relationships = []

        elif name == "Related_Weakness" and self.weakness_relationships_tag:
            self.relationships.append(attrs.get("CWE_ID"))

        elif name == "Has_Member" and self.category_relationships_tag:
            self.relationships.append(attrs.get("CWE_ID"))

        elif name == "Related_Attack_Patterns":
            self.attack_relationships_tag = True
            self.related_attack_patterns = []

        elif name == "Related_Attack_Pattern" and self.attack_relationships_tag:
            self.related_attack_patterns.append(attrs.get("CAPEC_ID"))


    def characters(self, ch):
        if self.description_tag:
            self.description += ch.replace("       ", "")

    def endElement(self, name):
        if (
            name == "Description"
            and self.weakness_tag
            and not self.observed_examples
            and not self.potential_mitigations
            and not self.detection_methods
            and not self.alternate_terms
        ):
            self.description_tag = False
            self.description = self.description
            self.cwe[-1]["Description"] = self.description.replace("\n", "")
        if name == "Summary" and self.category_tag:
            self.description_tag = False
            self.description = self.description
            self.cwe[-1]["Description"] = self.description.replace("\n", "")
        elif name == "Weakness" and self.weakness_tag:
            self.weakness_tag = False
        elif name == "Category" and self.category_tag:
            self.category_tag = False

        elif name == "Related_Weaknesses" and self.weakness_tag:
            self.weakness_relationships_tag = False
            self.cwe[-1]["related_weaknesses"] = self.relationships

        elif name == "Relationships" and self.category_tag:
            self.category_relationships_tag = False
            self.cwe[-1]["relationships"] = self.relationships

        elif name == "Related_Attack_Patterns":
            self.attack_relationships_tag = False
            self.cwe[-1]["related_attacks"] = self.related_attack_patterns

        elif name == "Observed_Examples":
            self.observed_examples = False

        elif name == "Potential_Mitigations":
            self.potential_mitigations = False

        elif name == "Detection_Methods":
            self.detection_methods = False

        elif name == "Alternate_Terms":
            self.alternate_terms = False

# Create a progress bar.
def progressBar(it, prefix="Preparing ", size=50):
    count = len(it)

    def _show(_i):
        if count != 0 and sys.stdout.isatty():
            x = int(size * _i / count)
            sys.stdout.write("%s[%s%s] %i/%i\r" % (prefix, "#" * x, " " * (size - x), _i, count))
            sys.stdout.flush()

    _show(0)
    for i, item in enumerate(it):
        yield item
        _show(i + 1)
    sys.stdout.write("\n")
    sys.stdout.flush()

# Generate a database with simplified CWE structure in CSV formats.
def generateDB():
    parser = make_parser()
    ch = CWEHandler()
    parser.setContentHandler(ch)
    cwe_dic_name = config.cwe_dic_path +'cwe1000.xml'
    parser.parse(cwe_dic_name)
    cweList=[]
    for cwe in progressBar(ch.cwe):
        description = cwe['Description'].replace("\t\t\t\t\t", " ")
        name = cwe['name']
        id = cwe['id']
        id = 'CWE-' + id
        status = cwe['status']
        weaknessabs = cwe['weaknessabs']
        if 'related_attacks' in cwe:
            related_attacks = cwe['related_attacks']
        else:
            related_attacks = 'Missing Data'
        if 'related_weaknesses' in cwe:
            related_weaknesses = cwe['related_weaknesses']
        else:
            related_weaknesses = 'Missing Data'

        new_row = {
            'CWEID' : id,
            'Name' : name,
            'Status' : status,
            'Description' : description,
            'WeaknessABS' : weaknessabs,
            'RelatedWeakness' : related_weaknesses,
            'RelatedAttack' : related_attacks
        }
        cweList.append(new_row)
    cweInfo = pd.DataFrame(cweList)
    return cweInfo


if __name__ == '__main__':
    db = generateDB()

