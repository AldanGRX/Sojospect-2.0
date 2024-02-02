import requests
import json
import hashlib
from urllib.parse import urlsplit
import os.path
import mysql.connector
import configparser
import sys
from urllib.parse import urljoin
from os.path import dirname
sys.path.append(dirname(dirname(f'{__file__}')))
from v2.yaml_vuln import vuln_extract



def recurse_dir(files,directory_queue, search, results, dir_string=''):
    dir_count = 0
    for record in files:
        if(record['type'] == "directory"):
            directory_queue.append(record)
            dir_count+=1
        elif(record['type'] == "file" and record['name']==search):
            return dir_string+'/'+record['name']
    if(dir_count == 0):
        return None
    for v in directory_queue:    
        val = recurse_dir(v['files'],[],search,results,dir_string=dir_string+'/'+v['name'])
        if(val != None):
            results.append(val)

def compare_version(package_version,versionEndIncluding, versionEndExcluding, versionStartIncluding, versionStartExcluding):
    vulnerable = False
    if package_version != None:
        if versionEndIncluding != None:
            vulnerable =  package_version <= versionEndIncluding
            if not vulnerable:
                return vulnerable
        if versionEndExcluding != None:
            vulnerable =  package_version < versionEndExcluding
            if not vulnerable:
                return vulnerable
        if versionStartIncluding != None:
            vulnerable =  package_version >= versionStartIncluding
            if not vulnerable:
                return vulnerable
        if versionStartExcluding != None:
            vulnerable =  package_version > versionStartExcluding
            if not vulnerable:
                return vulnerable
        return True
    else: 
        return False

def vuln_components(package, package_version):
    headers = {'apiKey':'4ec139bd-393a-4514-9288-80a331d7caec'}
    resp = requests.get(f"https://services.nvd.nist.gov/rest/json/cves/2.0?virtualMatchString=cpe:2.3:*:{package}:*:*:*:*:*", headers=headers)
    vulnerabilities = []
    if( resp.status_code == 200):
        json_obj = json.loads(resp.text)
        for index in range(len(json_obj['vulnerabilities'])):
            cve_id = json_obj['vulnerabilities'][index]['cve']['id']
            description = ""
            for row in json_obj['vulnerabilities'][index]['cve']['descriptions']:
                if row['lang']=='en':
                    description = row['value']
                    break

            versionEndIncluding=None
            versionEndExcluding=None
            versionStartIncluding=None
            versionStartExcluding=None
            version=None
            for row in json_obj['vulnerabilities'][index]['cve']['configurations']:
                for node in row['nodes']:
                    for value in node['cpeMatch']:
                        if package not in value['criteria']:
                            break
                        if 'versionEndIncluding' in value.keys():
                            versionEndIncluding = value['versionEndIncluding']
                        if 'versionEndExcluding' in value.keys():
                            versionEndExcluding = value['versionEndExcluding']
                        if 'versionStartIncluding' in value.keys():
                            versionStartIncluding = value['versionStartIncluding']
                        if 'versionStartExcluding' in value.keys():
                            versionStartExcluding = value['versionStartExcluding']
                    for value in node['cpeMatch']:
                        if versionEndIncluding==None and versionEndExcluding==None and versionStartIncluding==None and versionStartExcluding==None and package in value['criteria']:
                            criteria_list = value['criteria'].split(':')
                            version = criteria_list[5] if criteria_list[6] == '*' else criteria_list[5]+'-'+criteria_list[6]

            if versionEndIncluding==None and versionEndExcluding==None and versionStartIncluding==None and versionStartExcluding==None:
                if package_version != None and version == package_version:
                    vulnerabilities.append({"CVE":cve_id, "Description":description})
            else:
                vulnerable = compare_version(package_version, versionEndIncluding, versionEndExcluding, versionStartIncluding, versionStartExcluding)
                if vulnerable:
                    vulnerabilities.append({"CVE":cve_id, "Description":description})
    return vulnerabilities        

if __name__ == "__main__":
    user_input = sys.argv[1] # this is the domain
    scan_id = int(sys.argv[2])

urls=[]
config = configparser.ConfigParser()
config.read("config.ini")

#Function here to get the list of javascripts
with open('crawl.txt','r') as crawl_file:
    for i in (crawl_file.readlines()):
        data_dict = json.loads(i) #Data is now a dictionary from json loads
        urls.append(data_dict['URL'])

possible_packagenames = {}
#Extract package name from filename, first field
for url in urls:
    if '.js' in url:
        filename = os.path.split(urlsplit(url).path)[1]
        # possible_packagename = filename.split('.')[0]
        if filename in possible_packagenames:
            possible_packagenames[filename].append(url)
        else:
            possible_packagenames[filename] = [url]

vulnerabilities_dict = {}
#Extract all version numbers for the package
for filename, urls in possible_packagenames.items():
    package = filename.split('.')[0]
    resp = requests.get(f"https://registry.npmjs.com/{package}")
    if( resp.status_code == 200):
        resp_json = json.loads(resp.text)
        if not 'versions' in resp_json:
            continue
        version_numbers = resp_json['versions'].keys()
        # print(version_numbers)
        for url in urls:
            try:
                temp_resp = requests.get(url)
            except requests.exceptions.MissingSchema:
                temp_resp = requests.get(urljoin('https://chmsdemo.greenfossil.com',url))
            for v in version_numbers:
                if v in temp_resp.text:
                    
                    resp = requests.get(f"https://data.jsdelivr.com/v1/package/npm/{package}@{v}")
                    resp_json = json.loads(resp.text)
                    files = resp_json['files']
                    search =filename
                    results = []
                    recurse_dir(files,[],search,results)
                    
                    if len(results) == 0:
                        continue

                    for file_path in results:
                        resp = requests.get(f"https://cdn.jsdelivr.net/npm/{package}@{v}"+file_path)
                        hasher = hashlib.sha1(''.join(resp.text.split()).encode())
                        cdn_hash = hasher.hexdigest()
                        try:
                            resp = requests.get(url)
                        except requests.exceptions.MissingSchema:
                            resp = requests.get('https://chmsdemo.greenfossil.com'+url)
                        hasher = hashlib.sha1(''.join(resp.text.split()).encode())
                        web_hash = hasher.hexdigest()
                        if(cdn_hash==web_hash):
                            #Verified, it is indeed this version
                            vulnerabilities = vuln_components(package, v)
                            if len(vulnerabilities) > 0:
                                vulnerabilities_dict[f"{package}@{v}"] = vulnerabilities
                            break
                    else:
                        continue
                    break
if(len(vulnerabilities_dict) > 0):
    db_host = config.get('SQL Database', 'db_host')
    db_user = config.get('SQL Database', 'db_user')
    db_password = config.get('SQL Database', 'db_password')

    db_connection = mysql.connector.connect(
        host=db_host,
        user=db_user,
        password=db_password,
        database="vulnerabilities"
    )

    db_cursor = db_connection.cursor()
    cwe_id = "CWE-1352"
    # Insert a row into the MySQL table
    vuln_yml = vuln_extract(cwe_id)
    name = vuln_yml["name"]
    vulnerabilities_dict_json = json.dumps(vulnerabilities_dict)
    insert_query = "INSERT INTO vulnerabilities (scan_id, vulnerability_name, vulnerability_id, url, additional_information) VALUES (%s, %s, %s, %s, %s)"
    values = []
    values.append([scan_id,name,cwe_id,user_input, vulnerabilities_dict_json])
    db_cursor.executemany(insert_query, values)# Insert multiple rows together
    db_connection.commit()

    db_cursor.close()
    db_connection.close()



   
