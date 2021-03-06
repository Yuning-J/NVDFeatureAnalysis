# Software is free software released under the "GNU General Public License v3.0"
# Copyright (c) 2022 Yuning-Jiang - yuning.jiang17@gmail.com

import requests
from bs4 import BeautifulSoup
import os, sys, inspect
import config
current_dir = os.path.dirname(os.path.abspath(inspect.getfile(inspect.currentframe())))
parent_dir = os.path.dirname(current_dir)
sys.path.insert(0, parent_dir)


def crawlThreatLabels():
    link = 'https://www.cvedetails.com/vulnerability-list.php?vendor_id=0&product_id=0&version_id=0&page=1&hasexp=0&opdos=1&opec=0&opov=0&opcsrf=0&opgpriv=0&opsqli=0&opxss=0&opdirt=0&opmemc=0&ophttprs=0&opbyp=0&opfileinc=0&opginf=0&cvssscoremin=0&cvssscoremax=0&year=0&month=0&cweid=0&order=1&trc=21357&sha=38745b427397c23f6ed92e0ed2d3e114da828672'
    max_page_idx_list = []
    for i in range(13):
        cat_list = ['0'] * 13
        cat_list[i] = '1'
        dos, execution, overflow, memc, sqli, xss, dirtra, httprs, bypass, infor, gainpre, csrf, fileinc = cat_list
        page_num = 1
        link = 'https://www.cvedetails.com/vulnerability-list.php?vendor_id=0&product_id=0&version_id=0&page=' + str(
            page_num) + '&hasexp=0&opdos=' + dos + '&opec=' + execution + '&opov=' + overflow + '&opcsrf=' + csrf + '&opgpriv=' + gainpre + '&opsqli=' + sqli + '&opxss=' + xss + '&opdirt=' + dirtra + '&opmemc=' + memc + '&ophttprs=' + httprs + '&opbyp=' + bypass + '&opfileinc=' + fileinc + '&opginf=' + infor + '&cvssscoremin=0&cvssscoremax=0&year=0&month=0&cweid=0&order=1&trc=28068&sha=0ea5fbc52190c28f2a1c51aca205b315bc4c6509'
        page = requests.get(link, timeout=60, headers={'User-Agent': "Magic Browser"})

        content = BeautifulSoup(page.content).get_text()

        keyword_section = content.replace('\n', ' ')

        loc_1 = keyword_section.find('This Page)')
        loc_2 = keyword_section.find('How does it work? ')
        max_page_idx = keyword_section[loc_1 + 10:loc_2].split('   	')[0].strip().split()[-1]
        print(max_page_idx)
        max_page_idx_list.append(max_page_idx)

    name_cat = ['dos', 'execution', 'overflow', 'memc', 'sqli', 'xss', 'dirtra', 'httprs',  'bypass', 'infor', 'gainpre', 'csrf',  'fileinc' ]
    sha_value_cat = ['38745b427397c23f6ed92e0ed2d3e114da828672',
                 '0ea5fbc52190c28f2a1c51aca205b315bc4c6509',
                 '363372bbc3616054065946a39f4fa589eb5f0f04',
                 '5829c45b747ab5143004640f312c7f72e5b102db',
                 '1b24fccb15090079e49c0131be821c96dc2f001c',
                 'e3bb5586965f5a13bfaa78233a10ebc3f9606d12',
                 '69098b0b30799b9520bf468c7bc060a7f756abf9',
                 'd5623136f5150876a7dfba54b38fc96fe135993c',
                 '7c71486574161a851e392e2e9dcdfea2cde521c3',
                 '1f368a2d3fc25689cc46e4dcb206b4d6103aaab7',
                 '2f1f77e26ecf09cf8b4f251b1efc2b4bcad02050',
                 'e2c3963a5b4ac67dc5dc9fe39ff95f846162e52d',
                 '4160b1b268ed8bcd97bdd927802ef4922995d3d2']
    CVE_id_list_by_cat = []
    try:
        for cat_idx in range(13)[0:]:
            cat_list = ['0'] * 13
            cat_list[cat_idx] = '1'
            sha_value = sha_value_cat[cat_idx]
            dos, execution, overflow, memc, sqli, xss, dirtra, httprs, bypass, infor, gainpre, csrf, fileinc = cat_list
            max_page_num = int(max_page_idx_list[cat_idx])
            print('crawling the CVE ids in the ' + str(cat_idx) + ' category...')
            CVE_id_list_this_cat = []

            page_num = 1
            cve_cnt = 0
            while page_num <= max_page_num:
                link = 'https://www.cvedetails.com/vulnerability-list.php?vendor_id=0&product_id=0&version_id=0&page=' + str(
                    page_num) + '&hasexp=0&opdos=' + dos + '&opec=' + execution + '&opov=' + overflow + '&opcsrf=' + csrf + '&opgpriv=' + gainpre + '&opsqli=' + sqli + '&opxss=' + xss + '&opdirt=' + dirtra + '&opmemc=' + memc + '&ophttprs=' + httprs + '&opbyp=' + bypass + '&opfileinc=' + fileinc + '&opginf=' + infor + '&cvssscoremin=0&cvssscoremax=0&year=0&month=0&cweid=0&order=1&trc=28068&sha=' + sha_value
                page = requests.get(link, timeout=60, headers={'User-Agent': "Magic Browser"})
                print('category ' + str(cat_idx) + ', page ' + str(page_num) + ', cve count ' + str(cve_cnt), link)
                content = BeautifulSoup(page.content).get_text()
                content_lines_list = content.split('\n')
                for line in content_lines_list:
                    if line.startswith('CVE-'):
                        CVE_id_list_this_cat.append(line.strip())
                        cve_cnt += 1
                page_num += 1
            CVE_id_list_by_cat.append(CVE_id_list_by_cat)

            f_cve_id_cat_file = open(config.cveDetails_path + 'cve_id' + name_cat[cat_idx], 'w')
            idx = 1
            for cve in CVE_id_list_this_cat:
                f_cve_id_cat_file.write(str(idx) + '\t' + cve + '\n')
                idx += 1

        print(CVE_id_list_by_cat)

    except requests.exceptions.HTTPError as errh:
        print("Http Error: " + str(errh) + " Please check: " + link)
    except requests.exceptions.ConnectionError as errc:
        print("Error Connecting:" + str(errc) + " Please check: " + link)
    except requests.exceptions.Timeout as errt:
        print("Timeout Error:" + str(errt) + " Please check: " + link)
    except requests.exceptions.RequestException as err:
        print("Other errors!" + str(err) + " Please check: " + link)

if __name__ == '__main__':
     crawlThreatLabels()
