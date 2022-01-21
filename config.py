import os

# Change to the absolute path of your project location.
absolute_path = '/Users/aurelie/PycharmProjects/CPSLab1/'
project_path = absolute_path + 'NVDdata_FeatureAnalysis/'


# ================= label related ====================
cat_list = ['memc', 'cve_idbypass', 'cve_idcsrf', 'dirtra', 'dos', 'execution', 'fileinc', 'gainpre', 'httprs', 'infor', 'overflow',
            'sqli', 'xss']
num_cat_dict = dict()
for cat in cat_list:
    num_cat_dict[len(num_cat_dict)] = cat


# ================= original dataset paths ====================
cwe_dic_path = project_path + 'originalDataset/cweOriginal/'
cveDetails_path = project_path + 'originalDataset/cveIDThreatType/'
nvd_json_path = project_path + 'originalDataset/reportNVDinJSON/'
nvd_zip_path = project_path + 'originalDataset/reportNVDzip/'


# ================= generated dataset paths ====================
report_CWECAPEC_path = project_path + 'labelledDataset/reportsWithCWECAPECLabels/'
report_threat_path = project_path + 'labelledDataset/reportsWithThreatLabels/'
report_CVSSV2_path = project_path + 'labelledDataset/reportsWithCVSSV2Labels/'
report_CVSSV3_path = project_path + 'labelledDataset/reportsWithCVSSV3Labels/'

