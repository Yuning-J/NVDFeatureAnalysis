# NVD Data Analysis and Visualisation

## About the Tool
Some static analysis and visualisation for vulnerability instances disclosed in [NVD](https://nvd.nist.gov/vuln/full-listing). This tool also generates several datasets with various labels ([CWE](https://cwe.mitre.org/index.html) labels, [CAPEC](https://capec.mitre.org/index.html) labels, [CVSS](https://www.first.org/cvss/specification-document) labels, [cvedetails](https://www.cvedetails.com/vulnerabilities-by-types.php) labels) that can be used for further text-mining usage. You can directly employ the generated dataset, or apply this tool to get your own. 


## Generate your own data
Play with vulnerability reports as you want. 

- Step 1: Clone the repo using the following command:
```bash
git clone https://github.com/Yuni0217/NVDdata-analysis-and-visualisation.git 
```
- Step 2: Create a virtual environment, also change the absolute path in the config.py file.

- Step 3: Install requirements using `pip`:
```bash
pip install -r requirements.txt
```
- Step 4: Download datasets from NVD feeds and assign CWE/CVSS/threat labels.
```bash
python src./getNVDdata.py that downlads datasets from NVD feeds.
python src./assignThreatLabels.py that assigns threat labels to NVD vulnerabilities.
python src./assignCWECAPECLabels.py that assigns CWE and CAPEC labels to NVD vulnerabilities.
python src./assignCVSSLabels.py that assigns threat labels to NVD vulnerabilities.
```

## Directly use historical datasets
We only generate the dataset for 2002-2003 and 2020-2021 to save some Github storage, but you can easily change the year parameters and generate reports of any year within (2002-2022) you want. 
- Vulnerability dataset (2002-2003, 2020-2021) with [CWE](https://cwe.mitre.org/index.html) labels, CWE names, and cross-linked [CAPEC](https://capec.mitre.org/index.html) labels. 
- Vulnerability dataset (2002-2003, 2020-2021) with threat labels assigned by [cvedetails](https://www.cvedetails.com/vulnerabilities-by-types.php).
- Vulnerability dataset (2002-2003, 2020-2021) with detailed CVSS Version2 labels.
- Vulnerability dataset (2002-2003, 2020-2021) with detailed CVSS Version3 labels.
