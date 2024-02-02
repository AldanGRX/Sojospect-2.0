import sslyze
import requests
import json
import sys
import configparser
import mysql.connector
from requests.adapters import HTTPAdapter, Retry
from bs4 import BeautifulSoup as soup
from os.path import dirname
sys.path.append(dirname(dirname(f'{__file__}')))
from v2.yaml_vuln import vuln_extract

if __name__ == "__main__":
    user_input = sys.argv[1] # this is the domain
    scan_id = int(sys.argv[2])

config = configparser.ConfigParser()
config.read("config.ini")
s = requests.Session() # Setting up a requests session to persist parameters
retries = Retry(total=5,backoff_factor=0.1)
s.mount('http://',HTTPAdapter(max_retries=retries))
s.mount('https://',HTTPAdapter(max_retries=retries))

url = user_input.replace('http://',"").replace("https://","")
all_scan_requests = [sslyze.ServerScanRequest(sslyze.ServerNetworkLocation(url))]
scanner = sslyze.Scanner()
scanner.queue_scans(all_scan_requests)

accepted_ciphers = []
is_vulnerable_to_heartbleed = False
weak_ssl = False
logjam = False
heartbleed = False
deprecated = False
weak_ciphers = []

for server_scan_result in scanner.get_results():
    is_vulnerable_to_heartbleed= server_scan_result.scan_result.heartbleed.result.is_vulnerable_to_heartbleed
    if(server_scan_result.scan_result.ssl_2_0_cipher_suites.status == sslyze.ScanCommandAttemptStatusEnum.COMPLETED):
        #Process if completed
        #success
        for accepted in server_scan_result.scan_result.ssl_2_0_cipher_suites.result.accepted_cipher_suites:
            accepted_ciphers.append([accepted,"SSL2.0"])
    if(server_scan_result.scan_result.ssl_3_0_cipher_suites.status == sslyze.ScanCommandAttemptStatusEnum.COMPLETED):
        #Process if completed
        #success
        for accepted in server_scan_result.scan_result.ssl_3_0_cipher_suites.result.accepted_cipher_suites:
            accepted_ciphers.append([accepted,"SSL3.0"])
    if(server_scan_result.scan_result.tls_1_0_cipher_suites.status == sslyze.ScanCommandAttemptStatusEnum.COMPLETED):
        #Process if completed
        #success
        for accepted in server_scan_result.scan_result.tls_1_0_cipher_suites.result.accepted_cipher_suites:
            accepted_ciphers.append([accepted,"TLS1.0"])
    if(server_scan_result.scan_result.tls_1_1_cipher_suites.status == sslyze.ScanCommandAttemptStatusEnum.COMPLETED):
        #Process if completed
        #success
        for accepted in server_scan_result.scan_result.tls_1_1_cipher_suites.result.accepted_cipher_suites:
            accepted_ciphers.append([accepted,"TLS1.1"])
    if(server_scan_result.scan_result.tls_1_2_cipher_suites.status == sslyze.ScanCommandAttemptStatusEnum.COMPLETED):
        #Process if completed
        #success
        for accepted in server_scan_result.scan_result.tls_1_2_cipher_suites.result.accepted_cipher_suites:
            accepted_ciphers.append([accepted,"TLS1.2"])
    if(server_scan_result.scan_result.tls_1_3_cipher_suites.status == sslyze.ScanCommandAttemptStatusEnum.COMPLETED):
        #Process if completed
        #success
        for accepted in server_scan_result.scan_result.tls_1_3_cipher_suites.result.accepted_cipher_suites:
            accepted_ciphers.append([accepted,"TLS1.3"])

for row in accepted_ciphers:
    cipher = row[0].cipher_suite
    key_ex = row[0].ephemeral_key
    tls_ssl = row[1]
    
    resp = s.get(f"https://ciphersuite.info/api/cs/{cipher.name}")
    print(f"{cipher.name}: {json.loads(resp.text)[cipher.name]['security']}")
    if json.loads(resp.text)[cipher.name]['security'] == 'weak':
        #Extracting text from the page, since api does not do that
        # try:
        resp = s.get(f"https://ciphersuite.info/cs/{cipher.name}")
        _soup = soup(resp.text, 'html.parser')
        danger_text = _soup.find_all("div",{"class":["alert-danger","alert-warning", "alert-info"]})
        all_para_text = []
        for line in danger_text:
            para_text = ""
            if (line.find('p')):
                para_text = line.p.get_text()
            all_para_text.append(para_text)
        #End
        
        weak_ciphers.append({
            "name":cipher.name,
            "issues":all_para_text
        })
        weak_ssl = True
    if("CBC" in cipher.name and key_ex != None and key_ex.type_name=='DH' and key_ex.size<=1024):
        #DHE key size <= 1024 : Vulnerable to Logjam
        print("Vulnerable to Logjam")
        logjam = True
    #<=TLS 1.1 is deprecated as stated by nuclei 
    if(tls_ssl not in ["TLS1.2","TLS1.3"]):
        print("Using deprecated TLS version")
        deprecated = True
#Test for heartbleed
if(is_vulnerable_to_heartbleed):
    print("Vulnerable to heartbleed")
    heartbleed = True

if (heartbleed or deprecated or logjam or weak_ssl) :
    print("Weak ssl detected")
    db_host = config.get('SQL Database', 'db_host')
    db_user = config.get('SQL Database', 'db_user')
    db_password = config.get('SQL Database', 'db_password')

    db_connection = mysql.connector.connect(
        host=db_host,
        user=db_user,
        password=db_password,
        database="vulnerabilities"
    )

    additional_information = {
        "weak_ssl":weak_ciphers,
        "heartbleed":heartbleed,
        "deprecated":deprecated,
        "logjam":logjam
    }
    additional_information_json = json.dumps(additional_information)
    db_cursor = db_connection.cursor()
    cwe_id = "CUST-Weak-SSL"
    # Insert a row into the MySQL table
    vuln_yml = vuln_extract(cwe_id)
    name = vuln_yml["name"]

    insert_query = "INSERT INTO vulnerabilities (scan_id, vulnerability_name, vulnerability_id, url, additional_information) VALUES (%s, %s, %s, %s, %s)"
    values = []
    values.append([scan_id,name,cwe_id,user_input,additional_information_json])
    db_cursor.executemany(insert_query, values)# Insert multiple rows together
    db_connection.commit()

    db_cursor.close()
    db_connection.close()