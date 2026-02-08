cer_root_dir = "./mutation/test/cert_json/"
mft_root_dir = "./mutation/test/mft_json/"
pre_root_dir = "rsync://rpki.afrinic.net/repository/"

ta_file_path = cer_root_dir + "afrinic/AfriNIC.json"

import os
import json
import xml.etree.ElementTree as ET
from xml.dom import minidom
import logging

logging.basicConfig(
    level=logging.INFO,  
    format="%(asctime)s - %(levelname)s - %(message)s", 
    handlers=[
        logging.FileHandler("./my_repo/parse_cfg.log"), 
        logging.StreamHandler()  
    ]
)

def get_all_json_paths(path):
    all_json_files = [] 
    for root, dirs, files in os.walk(path):
        for file in files:
            if file.endswith('.json'):
                all_json_files.append(os.path.join(root, file))
    return all_json_files

all_certs_path = get_all_json_paths(cer_root_dir)
all_mft_path = get_all_json_paths(mft_root_dir)

def remote_to_local_path(remote_path):
    if remote_path.endswith(".mft"):
        mft_remote_path = remote_path
        mft_remote_path = mft_remote_path.split("/")[-2:]   
        mft_remote_path = "/".join(mft_remote_path)
        mft_remote_path = mft_remote_path.replace(".mft", ".json")
        for mft in all_mft_path:
            if mft_remote_path in mft:
                return mft
        return None
    elif remote_path.endswith(".cer"):
        cer_remote_path = remote_path
        cer_remote_path = cer_remote_path.split("/")[-2:]   
        cer_remote_path = "/".join(cer_remote_path)
        cer_remote_path = cer_remote_path.replace(".cer", ".json")
        for cer in all_certs_path:
            if cer_remote_path in cer:
                return cer
        return None
    else:
        assert False, "The remote path is not a mft or cer file"
      
def get_file_lists_from_mft(mft_data):
    file_list = mft_data["content"]["encap_content_info"]["content"]["fileList"]
    all_files = []
    for i in file_list:
        all_files.append(i["file"])
    # print(all_files)
    return all_files

def get_sia_path_from_cert(cert_data):
    cert_data = cert_data["tbs_certificate"]
    cert_exts = cert_data["extensions"]
    for cert_ext in cert_exts:
        # print(cert_ext)
        if cert_ext["extn_id"] == "subject_information_access":
            # print(cert_ext["extn_value"])
            for i in cert_ext["extn_value"]:
                # print(i)
                if i["access_method"] == "ca_repository":
                    return i["access_location"]
    assert False, "No sia path found in the cert"

def extract_mft_from_cert(cert_data):
    cert_data = cert_data["tbs_certificate"]
    issuer = cert_data["subject"]["common_name"]
    cert_exts = cert_data["extensions"]
    mft_remote_path = None
    for cert_ext in cert_exts:
        # print(cert_ext)
        if cert_ext["extn_id"] == "subject_information_access":
            # print(cert_ext["extn_value"])
            for i in cert_ext["extn_value"]:
                if i["access_method"] == "id-ad-rpkiManifest":
                    mft_remote_path = i["access_location"]
                    break
    if mft_remote_path is None:
        assert False, "No mft path found in the cert"
    local_mft_path = remote_to_local_path(mft_remote_path)
    if local_mft_path is None:
        assert False, "No local mft path found for the cert"
    mft_json_file = json.load(open(local_mft_path, 'r'))
    eecerts = mft_json_file["content"]["certificates"]
    assert len(eecerts) == 1, "There should be only one ee cert in the mft"
    ee_cert = eecerts[0]
    issuer_to_check = ee_cert["tbs_certificate"]["issuer"]["common_name"]
    if issuer_to_check != issuer:
        assert False, "The issuer of the ee cert and the issuer of the cert do not match"
    return mft_json_file

def generate_xml(cert_name, sia_path, file_list):
    root = ET.Element("CertificateInfo")
    cert_element = ET.SubElement(root, "Certificate")
    ET.SubElement(cert_element, "Name").text = cert_name
    ET.SubElement(cert_element, "RsyncAddress").text = sia_path

    files_element = ET.SubElement(cert_element, "Files")
    for file in file_list:
        ET.SubElement(files_element, "File").text = file

    rough_string = ET.tostring(root, encoding="utf-8")
    reparsed = minidom.parseString(rough_string)
    pretty_xml = reparsed.toprettyxml(indent="  ")

    xml_output_path = f"./my_repo/{cert_name}.xml"
    os.makedirs(os.path.dirname(xml_output_path), exist_ok=True)
    with open(xml_output_path, "w", encoding="utf-8") as f:
        f.write(pretty_xml)
    logging.info(f"XML file generated at: {xml_output_path}")

def parse_lca_to_xml(cert_file_path):
    logging.info("Starting to parse LCA to XML: "+cert_file_path)
    with open(cert_file_path, 'r') as f:
        cert_data = json.load(f)
    sia_path = get_sia_path_from_cert(cert_data)
    logging.info(f"SIA path extracted: {sia_path}")
    mft_data = extract_mft_from_cert(cert_data)
    file_list = get_file_lists_from_mft(mft_data)
    remote_file_paths = [sia_path + i for i in file_list]
    crl_files = [i for i in remote_file_paths if i.endswith(".crl")]
    cer_files = [i for i in remote_file_paths if i.endswith(".cer")]
    mft_files = [i for i in remote_file_paths if i.endswith(".mft")]
    assert len(crl_files) == 1, "There should be only one crl file in the mft"
    assert len(mft_files) == 0, "There should be no mft file in the mft"
    generate_xml(
        cert_name=cert_file_path.split("/")[-1].replace(".json", ""),
        sia_path=sia_path,
        file_list=file_list
    )
    logging.info("XML file generated successfully: "+cert_file_path)
    for cer in cer_files:
        local_cer_path = remote_to_local_path(cer)
        parse_lca_to_xml(local_cer_path)
        

# parse_lca_to_xml(ta_file_path)

xml_dir = "./my_repo/"
all_xml_files = get_all_json_paths(xml_dir)
ta_xml_path = xml_dir + "AfriNIC.xml"

def xml_to_cfg(lca_xml_path):
    tree = ET.parse(lca_xml_path)
    root = tree.getroot()
    cert_info = root.find("Certificate")
    files = cert_info.find("Files")
    crl_files = [i.text for i in files if i.text.endswith(".crl")]
    cer_files = [i.text for i in files if i.text.endswith(".cer")]
    roa_files = [i.text for i in files if i.text.endswith(".roa")]
    cfg_tmp = ["DCA", "MFT"]
    for i in cer_files:
        cfg_tmp += xml_to_cfg(xml_dir + i.replace(".cer", ".xml"))
    for i in roa_files:
        cfg_tmp += ["ROA"]
    cfg_tmp += ["CRL"]
    return cfg_tmp
    
cfg_result = xml_to_cfg(ta_xml_path)
print(cfg_result)

def wirte_cfg_to_file(cfg_result, output_path):

    indent_level = 0    
    with open(output_path, 'w') as f:
        for item in cfg_result:
            if item == "MFT":
                indent_level += 1
            f.write("   " * indent_level + item + "\n")
            if item == "CRL":
                indent_level -= 1
wirte_cfg_to_file(cfg_result, "./cfg.txt")
