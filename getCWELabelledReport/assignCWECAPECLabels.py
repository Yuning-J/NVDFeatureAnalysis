import os, sys
import re
import csv
import json
import logging
from os import listdir
from os.path import join

def create_nvd_dict(year):
    filename = join("reportNVDinJSON/nvdcve-1.1-" + str(year) + ".json")
    with open(filename, encoding="utf8") as json_file:
        cve_dict = json.load(json_file)
    json_file.close()
    return(cve_dict)


def generate_nvd_with_cwe_capec_for_training():
    from weaknessCrawlerCWE import generateDB
    db = generateDB()

    filePath = "reportNVDinJSON"
    if not os.path.exists(filePath):
        logging.error("The path specified does not exist. Try update.py first")
        sys.exit(1)
    list = listdir("reportNVDinJSON/")
    number_files = len(list)

    for year in range(2020,2020 + number_files):
        year_in_string = str(year)
        vulnerability_dict = create_nvd_dict(year)
        fileName = 'NVD_'+ year_in_string + '_CWE_CAPEClabel.csv'
        with open('reportsWithCWEandCAPEC/' + fileName, 'w', newline='') as f_output:
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

def getCWENameCAPEC(db, cweID):
    selectedCWErow = db.loc[db['CWEID'] == cweID]
    name = selectedCWErow['Name'].values[0]
    capec = selectedCWErow['RelatedAttack'].values[0]
    return name,capec

def getIDfromCWEID(cweID):
    test = cweID
    text = [x.strip() for x in re.compile(r"(?<!\\)*:").split(test[4:])]
    text = text[0]
    return text

if __name__ == '__main__':
    generate_nvd_with_cwe_capec_for_training()




