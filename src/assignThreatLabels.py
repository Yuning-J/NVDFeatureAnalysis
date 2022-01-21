# Software is free software released under the "GNU General Public License v3.0"
# Copyright (c) 2022 Yuning-Jiang - yuning.jiang17@gmail.com

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

def generate_threattypes():
    list = listdir(config.nvd_json_path)
    number_files = len(list)
    for year in range(2002,2002 + number_files):
        year_in_string = str(year)
        cve_dict = create_nvd_dict(year)
        fileName = 'NVD_'+ year_in_string + '_ThreatLabel.csv'
        with open(config.report_threat_path + fileName, 'w', newline='') as f_output:
            csv_output = csv.writer(f_output)
            csv_output.writerow(['id', 'report','memc', 'bypass', 'csrf', 'dirtra', 'dos', 'execution', 'fileinc', 'gainpre', 'httprs', 'infor', 'overflow',
            'sqli', 'xss'])

            for item in cve_dict['CVE_Items']:
                cve_id = item['cve']['CVE_data_meta']['ID']
                report = item['cve']['description']['description_data'][0]['value']
                if not report.find("REJECT"):
                    continue

                memc = 0
                bypass = 0
                csrf = 0
                dirtra = 0
                dos = 0
                execution = 0
                fileinc = 0
                gainpre = 0
                httprs = 0
                infor = 0
                overflow = 0
                sqli = 0
                xss = 0

                name_cat = ['memc', 'bypass', 'csrf', 'dirtra', 'dos', 'execution', 'fileinc', 'gainpre', 'httprs', 'infor', 'overflow','sqli', 'xss']
                threat_list = [memc, bypass, csrf, dirtra, dos, execution, fileinc, gainpre, httprs, infor, overflow, sqli, xss]
                for cat_idx in range(13):
                    fobj = open(config.cveDetails_path + 'cve_id' + name_cat[cat_idx], 'r')
                    text = fobj.read().strip().split()
                    try:
                        s = cve_id
                        if s == "":
                            continue
                        elif s in text:
                            threat_list[cat_idx]=1
                        else:
                            threat_list[cat_idx]=0

                    except Exception as e:
                        print(e)

                memc = threat_list[0]
                bypass = threat_list[1]
                csrf = threat_list[2]
                dirtra = threat_list[3]
                dos = threat_list[4]
                execution = threat_list[5]
                fileinc = threat_list[6]
                gainpre = threat_list[7]
                httprs = threat_list[8]
                infor = threat_list[9]
                overflow = threat_list[10]
                sqli = threat_list[11]
                xss = threat_list[12]

                csv_output.writerow([cve_id, report,memc, bypass, csrf, dirtra, dos, execution, fileinc, gainpre, httprs, infor, overflow, sqli, xss])


if __name__ == '__main__':
     generate_threattypes()

