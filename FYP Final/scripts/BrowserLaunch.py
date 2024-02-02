import sys, json
import requests
import configparser
import mysql.connector
import json
import threading
from urllib.parse import urlparse
from seleniumwire import webdriver
from webdriver_manager.chrome import ChromeDriverManager
from selenium.webdriver.chrome.service import Service
from urllib.parse import parse_qs
from time import sleep
from os.path import dirname
sys.path.append(dirname(dirname(f'{__file__}')))
from v2.yaml_vuln import vuln_extract
from SQL_injection import sql_injection
from XSS_injection import xss_injection
from SSRF_injection import ssrf

def save_vuln_to_db(cwe_id, affected_endpoints) :
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
    # cwe_id = "CWE-89"
    # Insert a row into the MySQL table
    vuln_yml = vuln_extract(cwe_id)
    name = vuln_yml["name"]

    insert_query = "INSERT INTO vulnerabilities (scan_id, vulnerability_name, vulnerability_id, url, additional_information) VALUES (%s, %s, %s, %s, %s)"
    values = []
    vulnerable_endpoints = {
        "results" : affected_endpoints
    }
    error_dict = json.dumps(vulnerable_endpoints)
    values.append([scan_id,name,cwe_id,user_input,error_dict])
    db_cursor.executemany(insert_query, values)# Insert multiple rows together
    db_connection.commit()

    db_cursor.close()
    db_connection.close()

# Define a request interceptor function
def my_request_interceptor(request):    
    # Do something with the intercepted request
    if (request.method).upper() == 'POST' or (request.method).upper() == 'PUT' :
        if request.method == 'POST' :
            method = requests.post
        elif request.method == 'PUT' :
            method = requests.put

        body_in_string = (request.body).decode('utf-8')
        
        if request.headers['Content-Type'] == 'application/json' :
            params = json.loads(body_in_string)
        else :
            params = {key: value[0] if len(value) == 1 else value for key, value in parse_qs(body_in_string).items()}
        
        if not any(request.url == x._args[1] for x in sql_threads) : # check if the endpoint is alr going to be requested
            thread = threading.Thread(target=sql_injection, args=(url, request.url, method, params))
            sql_threads.append(thread)

        if not any(request.url == x._args[1] for x in xss_threads) : # check if the endpoint is alr going to be requested
            thread = threading.Thread(target=xss_injection, args=(url, request.url, method, params))
            xss_threads.append(thread)

        if not any(request.url == x._args[1] for x in ssrf_threads) : # check if the endpoint is alr going to be requested
            resp = requests.post("https://webhook.site/token")
            token1 = json.loads(resp.text)["uuid"]
            thread = threading.Thread(target=ssrf, args=(url, request.url, method, params, token1))
            ssrf_threads.append(thread)
        

# code starts running from here 
if __name__ == "__main__":
    user_input = sys.argv[1] # this is the domain
    scan_id = int(sys.argv[2])

parsed_url = urlparse(user_input)
scheme = parsed_url.scheme
netloc = parsed_url.netloc
url = scheme + "://" + netloc

options = webdriver.ChromeOptions()
options.add_experimental_option("detach", True)
# Create a new instance of the Selenium Wire WebDriver
driver = webdriver.Chrome(chrome_options=options, service=Service(ChromeDriverManager().install()))

config = configparser.ConfigParser()
config.read("config.ini")
username = config.get('Advanced Scan Settings','scraping_username')
password = config.get('Advanced Scan Settings','scraping_password')
filename = config.get('Advanced Scan Settings', 'mapped_file')
scan_for_sql = config.get('Advanced Scan Settings','scan_for_sql')
scan_for_xss = config.get('Advanced Scan Settings','scan_for_xss')
sql_inject_all_eps = config.get('Advanced Scan Settings', 'sql_inject_all_eps')
xss_inject_all_eps = config.get('Advanced Scan Settings', 'xss_inject_all_eps')
ssrf_inject_all_eps = config.get('Advanced Scan Settings', 'ssrf_inject_all_eps')

######################## start of using selenium wire - pops up browser #######################
# Set the request interceptor
driver.request_interceptor = my_request_interceptor
driver.scopes=[netloc]
driver.get(url)
instructions_script = "PLEASE FOLLOW THE INSTRUCTIONS :\n\n1. Find all input fields and submit form.\n2. Once done, close the browser.\n3. Click 'OK' if understood the instruction."
driver.execute_script(f"alert(`{instructions_script}`);")
sleep(2) # wait for alert to appear

sql_threads = []
xss_threads = []
ssrf_threads = []

DISCONNECTED_MSG = 'Unable to evaluate script: no such window: target window already closed\nfrom unknown error: web view not found\n'
while True :
    # print(driver.get_log('driver'))
    if len(driver.get_log('driver')) == 0 :
        sleep(1)
        continue
    if driver.get_log('driver')[-1]['message'] == DISCONNECTED_MSG:
        break
    sleep(1)

print("Browser closed by user")
# start running the threads
if int(sql_inject_all_eps) == 1 :
    print("RUNNING SQL INJECTION THREADS NOW")
    for thread in sql_threads :
        thread.start()
        thread.join()
    print("SQL Injection - Finished\n")

if int(xss_inject_all_eps) == 1 :
    print("RUNNING XSS INJECTION THREADS NOW")
    for thread in xss_threads :
        thread.start()
        thread.join()
    print("XSS Injection - Finished\n")

if int(ssrf_inject_all_eps) == 1 :
    print("RUNNING SSRF INJECTION THREADS NOW")
    for thread in ssrf_threads :
        thread.start()
        thread.join()
    print("SSRF - Finished\n")

# read files
sql_vuln_file = 'injection-results/sql_vuln_endpoints.txt'
xss_vuln_file = 'injection-results/xss_vuln_endpoints.txt'
ssrf_vuln_file = 'injection-results/ssrf_vuln_endpoints.txt'
with open(sql_vuln_file, 'r') as file :
    sql_affected_urls = file.readlines()
    sql_affected_urls = [affected for affected in sql_affected_urls if affected != ""]

with open(xss_vuln_file, 'r') as file :
    xss_affected_urls = file.readlines()
    xss_affected_urls = [affected for affected in xss_affected_urls if affected != ""]

with open(ssrf_vuln_file, 'r') as file :
    vulnlist = {"internal": [], "external": []}
    ssrf_affected_urls = file.readlines()
    for line in ssrf_affected_urls:
        data = json.loads(line)
        endpoint = data.get("Endpoint")
        direction = data.get("direction")
        if endpoint and direction == "internal":
            vulnlist["internal"].append(endpoint)
        elif endpoint and direction == "external":
            vulnlist["external"].append(endpoint)
    print(vulnlist)

# clear file contents
with open(sql_vuln_file, 'w') as file :
    file.write('')
with open(xss_vuln_file, 'w') as file :
    file.write('')
with open(ssrf_vuln_file, 'w') as file :
    file.write('')

# check if there is vulnerable endpoints
if len(sql_affected_urls) > 0 :
    cwe_id = "CWE-89"
    save_vuln_to_db(cwe_id, sql_affected_urls)

if len(xss_affected_urls) > 0 :
    cwe_id = "CWE-79"
    save_vuln_to_db(cwe_id, xss_affected_urls)

if len(vulnlist['internal']) > 0 or len(vulnlist['external']) > 0:
    cwe_id = "CWE-918"
    db_host = config.get("SQL Database", "db_host")
    db_user = config.get("SQL Database", "db_user")
    db_password = config.get("SQL Database", "db_password")
    db_connection = mysql.connector.connect(
        host=db_host, user=db_user, password=db_password, database="vulnerabilities"
    )
    db_cursor = db_connection.cursor()
    # Insert a row into the MySQL table
    vuln_yml = vuln_extract(cwe_id)
    name = vuln_yml["name"]
    vulnerabilitylist_json = json.dumps(vulnlist)
    insert_query = "INSERT INTO vulnerabilities (scan_id, vulnerability_name, vulnerability_id, url, additional_information) VALUES (%s, %s, %s, %s, %s)"
    values = []
    values.append([scan_id, name, cwe_id, user_input, vulnerabilitylist_json])
    print(values)
    db_cursor.executemany(insert_query, values)  # Insert multiple rows together
    db_connection.commit()
    db_cursor.close()
    db_connection.close()