# Software is free software released under the "GNU General Public License v3.0"
# Copyright (c) 2022 Yuning-Jiang - yuning.jiang17@gmail.com

import re
import requests
import zipfile
import config
from os import listdir
from os.path import isfile, join

#Download NVD data feeds in JSON format. Ensure you have a folder called "zip" in the same directory.
def get_nvd_data():
    r = requests.get('https://nvd.nist.gov/vuln/data-feeds#JSON_FEED')
    for filename in re.findall("nvdcve-1.1-[0-9]*\.json\.zip",r.text):
        print(filename)
        r_file = requests.get("https://nvd.nist.gov/feeds/json/cve/1.1/" + filename, stream=True)
        with open(config.nvd_zip_path + filename, 'wb') as f:
            for chunk in r_file:
                f.write(chunk)

#Extract the JSON files from .zip files.
def unzip_data():
    files = [f for f in listdir(config.nvd_zip_path) if isfile(join(config.nvd_zip_path, f))]
    files.sort()
    for file in files:
        print("Opening: " + file)
        archive = zipfile.ZipFile(join(config.nvd_zip_path, file), 'r')
        with archive as f:
            f.extractall('json')

if __name__ == '__main__':
     get_nvd_data()
     unzip_data()
