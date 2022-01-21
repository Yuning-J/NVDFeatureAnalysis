# NVD Data Feature Analysis

<!-- PROJECT LOGO -->
<br />
<p align="center">
  <a href="https://github.com/Yuning-J/NVDdata_FeatureAnalysis">
  </a>
  <br />

  <!-- Badges -->
  <img src="https://img.shields.io/github/repo-size/Yuni0217/NVDdata_FeatureAnalysis?style=for-the-badge" alt="GitHub repo size" height="25">
  <img src="https://img.shields.io/github/last-commit/Yuni0217/NVDdata_FeatureAnalysis?style=for-the-badge" alt="GitHub last commit" height="25">
  <img src="https://img.shields.io/github/license/Yuni0217/NVDdata_FeatureAnalysis?style=for-the-badge" alt="License" height="25">
  <br />
  
  <h3 align="center">NVD Data Feature Analysis</h3>
  <p align="center">
    Analyse the features of NVD vulnerability reports in terms of CWE, CAPEC, threat and CVSS V2/V3.
 
  </p>
</p>

<!-- TABLE OF CONTENTS -->
## Table of Contents

* [About the Tool](#about-the-tool)
* [Generate your own data](#generate-your-own-data)
* [Directly use historical datasets](#directly-use-historical-datasets)
* [Some data visualisation](#some-data-visualisation)
* [Cite](#cite)

## About the Tool
Some static analysis and visualisation for vulnerability instances disclosed in [NVD](https://nvd.nist.gov/vuln/full-listing). This tool also generates several datasets with various labels ([CWE](https://cwe.mitre.org/index.html) labels, [CAPEC](https://capec.mitre.org/index.html) labels, [CVSS](https://www.first.org/cvss/specification-document) labels, [cvedetails](https://www.cvedetails.com/vulnerabilities-by-types.php) labels) that can be used for further text-mining usage. You can directly employ the generated dataset, or apply this tool to get your own. 

Some data samples are illustrated below.

- Report with CWE and CAPEC labels:
<p align="center">
<img src="https://github.com/Yuning-J/NVDdata-analysis-and-visualisation/blob/main/labelledDataset/samplePic/dataSample_cwecapec.png" alt="System" width="800px">
</p>

- Report with Threat labels:
<p align="center">
<img src="https://github.com/Yuning-J/NVDdata_FeatureAnalysis/blob/main/labelledDataset/samplePic/dataSample_threat.png" alt="System" width="850px">
</p>

- Report with CVSS Version 2 labels:
<p align="center">
<img src="https://github.com/Yuning-J/NVDdata-analysis-and-visualisation/blob/main/labelledDataset/samplePic/dataSample_cvssv2.png" alt="System" width="800px">
</p>

- Report with CVSS Version 3 labels:
<p align="center">
<img src="https://github.com/Yuning-J/NVDdata-analysis-and-visualisation/blob/main/labelledDataset/samplePic/dataSample_cvssv3.png" alt="System" width="800px">
</p>

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

Note that these datasets are compressed due to large sizes.

- [CWE/CAPEC Labelled Vulnerability dataset](https://github.com/Yuning-J/NVDdata-analysis-and-visualisation/tree/main/labelledDataset/reportsWithCVSSV2Labels) (2002-2021) with CWE labels and names, and CAPEC labels.  
- [Threat Labelled Vulnerability dataset](https://github.com/Yuning-J/NVDdata-analysis-and-visualisation/tree/main/labelledDataset/reportsWithThreatLabels) (2002-2021) with labels assigned by [cvedetails](https://www.cvedetails.com/vulnerabilities-by-types.php).
- [CVSS V2 Labelled Vulnerability dataset](https://github.com/Yuning-J/NVDdata-analysis-and-visualisation/tree/main/labelledDataset/reportsWithCVSSV2Labels) (2002-2021).
- [CVSS V3 Labelled Vulnerability dataset](https://github.com/Yuning-J/NVDdata-analysis-and-visualisation/tree/main/labelledDataset/reportsWithCVSSV3Labels)  (2002-2021).


## Some data visualisation

Check some of the visualisation documentations in the [Notebooks](https://github.com/Yuning-J/NVDdata_FeatureAnalysis/tree/main/visualisatio). Or create your own awesomes. Below are some of the examples:

- Vulnerability distribution in terms of access vector:
<p align="center">
<img src="https://github.com/Yuning-J/NVDdata_FeatureAnalysis/blob/main/labelledDataset/samplePic/V2AccessVectorDistribution.png" alt="System" width="700px">
</p>

- Threat distribution:
<p align="center">
<img src="https://github.com/Yuning-J/NVDdata_FeatureAnalysis/blob/main/labelledDataset/samplePic/CVEDetails2021.png" alt="System" width="780px">
</p>


## Cite

If you use this tool in your academic work you can cite it using

```bibtex
@Misc{nvddata_featureanalysis,
  author       = {Yuning Jiang},
  howpublished = {GitHub},
  month        = jan,
  title        = {{NVDdata FeatureAnalysis}},
  year         = {2022},
  url          = {https://github.com/Yuning-J/NVDdata_FeatureAnalysis},
}
```
