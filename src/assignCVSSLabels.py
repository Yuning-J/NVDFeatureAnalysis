# Software is free software released under the "GNU General Public License v3.0"
# Copyright (c) 2021 Yuning-Jiang - yuning.jiang17@gmail.com

import json
import csv
import pandas as pd
from os import listdir
from os.path import join
import config

def create_nvd_dict(year):
    path = config.nvd_json_path + 'nvdcve-1.1-'
    filename = join(path + str(year) + ".json")
    with open(filename, encoding="utf8") as json_file:
        cve_dict = json.load(json_file)
    json_file.close()
    return(cve_dict)

def generate_CVSSV3csv_for_training():
    list = listdir(config.nvd_json_path)
    number_files = len(list)
    for year in range(2002,2002 + number_files):
        year_in_string = str(year)
        vulnerability_dict = create_nvd_dict(year)
        fileName = 'NVD_'+ year_in_string + '_CVSSV3_train.csv'
        with open(config.report_CVSSV3_path + fileName, 'w', newline='') as f_output:
            csv_output = csv.writer(f_output)
            csv_output.writerow(['CVE_ID', 'PublishTime','ModifyTime','Report','CVSSV3','AttackVector','AttackComplexity','PrivilegesRequired',
                                 'UserInteraction','Scope','ConfidentialityImpact','IntegrityImpact','AvailabilityImpact'])
            for item in vulnerability_dict['CVE_Items']:
                cve_id = item['cve']['CVE_data_meta']['ID']
                report = item['cve']['description']['description_data'][0]['value']
                publish = item['publishedDate']
                modify = item['lastModifiedDate']
                if not report.find("**REJECT**"):
                    continue
                if 'baseMetricV3' not in item['impact']:
                    continue
                elif 'baseMetricV3' in item['impact']:
                    cvssv3_base_score = item['impact']['baseMetricV3']['cvssV3']['baseScore']
                    attackVector = item['impact']['baseMetricV3']['cvssV3']['attackVector']
                    attackComplexity = item['impact']['baseMetricV3']['cvssV3']['attackComplexity']
                    privilegesRequired = item['impact']['baseMetricV3']['cvssV3']['privilegesRequired']
                    userInteraction = item['impact']['baseMetricV3']['cvssV3']['userInteraction']
                    scope = item['impact']['baseMetricV3']['cvssV3']['scope']
                    confidentialityImpact = item['impact']['baseMetricV3']['cvssV3']['confidentialityImpact']
                    integrityImpact = item['impact']['baseMetricV3']['cvssV3']['integrityImpact']
                    availabilityImpact = item['impact']['baseMetricV3']['cvssV3']['availabilityImpact']

                    csv_output.writerow([cve_id, publish, modify,report, cvssv3_base_score,
                                 attackVector, attackComplexity, privilegesRequired, userInteraction,
                                 scope, confidentialityImpact, integrityImpact, availabilityImpact])

def generate_CVSSV2csv_for_training():
    list = listdir(config.nvd_json_path)
    number_files = len(list)
    for year in range(2002,2002 + number_files):
        year_in_string = str(year)
        vulnerability_dict = create_nvd_dict(year)
        fileName = 'NVD_'+ year_in_string + '_CVSSV3_train.csv'
        with open(config.report_CVSSV2_path + fileName, 'w', newline='') as f_output:
            csv_output = csv.writer(f_output)
            csv_output.writerow(['CVE_ID', 'PublishTime','ModifyTime','Report','CVSSV2','AccessVector','AccessComplexity',
                                 'Authentication','ConfidentialityImpact','IntegrityImpact','AvailabilityImpact'])

            for item in vulnerability_dict['CVE_Items']:
                cve_id = item['cve']['CVE_data_meta']['ID']
                publish = item['publishedDate']
                modify = item['lastModifiedDate']
                report = item['cve']['description']['description_data'][0]['value']
                if not report.find("**REJECT**"):
                    continue

                if 'baseMetricV2' not in item['impact']:
                    continue

                elif 'baseMetricV2' in item['impact']:
                    cvssv2_base_score = item['impact']['baseMetricV2']['cvssV2']['baseScore']
                    accessVector = item['impact']['baseMetricV2']['cvssV2']['accessVector']
                    accessComplexity = item['impact']['baseMetricV2']['cvssV2']['accessComplexity']
                    authentication = item['impact']['baseMetricV2']['cvssV2']['authentication']
                    confidentialityImpact = item['impact']['baseMetricV2']['cvssV2']['confidentialityImpact']
                    integrityImpact = item['impact']['baseMetricV2']['cvssV2']['integrityImpact']
                    availabilityImpact = item['impact']['baseMetricV2']['cvssV2']['availabilityImpact']


                    csv_output.writerow([cve_id, publish, modify,report, cvssv2_base_score,
                                         accessVector,accessComplexity, authentication,confidentialityImpact, integrityImpact, availabilityImpact])

if __name__ == '__main__':
     generate_CVSSV3csv_for_training()
     generate_CVSSV2csv_for_training()
