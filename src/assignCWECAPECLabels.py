# Software is free software released under the "GNU General Public License v3.0"
# Copyright (c) 2022 Yuning-Jiang - yuning.jiang17@gmail.com

import os, sys
import csv
import json
import logging
from os import listdir
from os.path import join
import config

# Load NVD vulnerability reports.
def create_nvd_dict(year):
    path = config.nvd_json_path + 'nvdcve-1.1-'
    filename = join(path + str(year) + ".json")
    with open(filename, encoding="utf8") as json_file:
        cve_dict = json.load(json_file)
    json_file.close()
    return(cve_dict)

# Assign CWE labels, CWE names, CAPEC labels to NVD vulnerability reports.
def generate_nvd_with_cwe_capec_for_training():
    from weaknessCrawlerCWE import generateDB
    db = generateDB()
    #filePath = "reportNVDinJSON"
    #if not os.path.exists(filePath):
        #logging.error("The path specified does not exist. Try update.py first")
        #sys.exit(1)
    list = listdir(config.nvd_json_path)
    number_files = len(list)

    for year in range(2002,2002 + number_files):
        year_in_string = str(year)
        vulnerability_dict = create_nvd_dict(year)
        fileName = 'NVD_'+ year_in_string + '_CWE_CAPEClabel.csv'
        with open(config.report_CWECAPEC_path + fileName, 'w', newline='') as f_output:
            csv_output = csv.writer(f_output)
            csv_output.writerow(['CVEID', 'CWEID', 'VulnerabilityType','AttackPattern', 'Report'])
            for item in vulnerability_dict['CVE_Items']:
                cve_id = item['cve']['CVE_data_meta']['ID']
                report = item['cve']['description']['description_data'][0]['value']
                cweidList = []
                vulnerabilityTypeList = []
                capecIDfullList=[]
                if not report.find("**REJECT**"):
                    continue

                if len(item['cve']['problemtype']['problemtype_data'])>0:
                    if len(item['cve']['problemtype']['problemtype_data'][0]['description'])>0:
                        for cweValue in item['cve']['problemtype']['problemtype_data'][0]['description']:

                            try:
                                cwe_id = cweValue['value']

                                if ('NVD-CWE-Other' in cwe_id) or ('NVD-CWE-noinfo' in cwe_id):
                                    vulnerabilityType = ''
                                    capecIDlist = []
                                else:
                                    vulnerabilityType, capecIDlist = getCWENameCAPEC(db,cwe_id)
                                    if isinstance(capecIDlist, str):
                                        capecIDlist = []
                                    else:
                                        capecIDlist = capecIDlist
                                for capec in capecIDlist:
                                    capecIDfullList.append(capec)
                                cweidList.append(cwe_id)
                                vulnerabilityTypeList.append(vulnerabilityType)

                            except IndexError:
                                cwe_id = ""
                    else:
                        cweidList = []
                        vulnerabilityTypeList = []
                        capecIDfullList = []
                else:
                    cweidList = []
                    vulnerabilityTypeList = []
                    capecIDfullList = []

                csv_output.writerow([cve_id, cweidList, vulnerabilityTypeList,capecIDfullList, report])

# Use CWE-IDs to fetch CWE names and related CAPEC attack patterns.
def getCWENameCAPEC(db, cweID):
    selectedCWErow = db.loc[db['CWEID'] == cweID]
    name = selectedCWErow['Name'].values[0]
    capec = selectedCWErow['RelatedAttack'].values[0]
    return name,capec

if __name__ == '__main__':
    generate_nvd_with_cwe_capec_for_training()




