import sys
import requests
import configparser
import json
from time import sleep
from urllib.parse import urlparse
from os.path import dirname
sys.path.append(dirname(dirname(f'{__file__}')))
import subprocess
from seleniumwire import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.by import By 
from selenium.webdriver.common.keys import Keys
from seleniumBot import login_get_cookie_jar
# for ssrf
from v2.yaml_vuln import vuln_extract
import mysql.connector
# import injection functions
from SQL_injection import sql_tryauto
from XSS_injection import xss_tryauto
from SSRF_injection import tryssrf

if __name__ == "__main__":
    user_input = sys.argv[1] # this is the domain
    scan_id = int(sys.argv[2])

parsed_url = urlparse(user_input)
scheme = parsed_url.scheme
netloc = parsed_url.netloc
url = scheme + "://" + netloc

config = configparser.ConfigParser()
config.read("config.ini")
username = config.get('Advanced Scan Settings','scraping_username')
password = config.get('Advanced Scan Settings','scraping_password')
filename = config.get('Advanced Scan Settings', 'mapped_file')
scan_for_sql = config.get('Advanced Scan Settings','scan_for_sql')
scan_for_xss = config.get('Advanced Scan Settings','scan_for_xss')
scan_for_ssrf = config.get("Advanced Scan Settings", "scan_for_ssrf")
sql_inject_all_eps = config.get('Advanced Scan Settings', 'sql_inject_all_eps')
xss_inject_all_eps = config.get('Advanced Scan Settings', 'xss_inject_all_eps')
ssrf_inject_all_eps = config.get('Advanced Scan Settings', 'ssrf_inject_all_eps')

def selenium_login(driver, url, username, password): # login using selenium
    login_url = url + '/login'
    driver.get(login_url)
    driver.find_element(By.ID, 'loginId').send_keys(username) # double check login id and password id fields
    driver.find_element(By.ID, 'password').send_keys(password, Keys.RETURN)
    sleep(5)
    return driver

def create_webdriver():
    try:
        # Try creating a Chrome webdriver
        chrome_options = Options()
        chrome_options.add_argument("headless")
        return webdriver.Chrome(options=chrome_options)
    except:
        try:
            # Try creating a Firefox webdriver
            firefox_options = webdriver.FirefoxOptions()
            firefox_options.add_argument("headless") 
            return webdriver.Firefox(options=firefox_options)
        except:
            try:
                from selenium.webdriver.edge.options import Options as EdgeOptions
                # Try creating an Edge webdriver
                options = EdgeOptions()
                options.use_chromium = True
                options.add_argument("headless")
                return webdriver.Edge(options=options)
            except:
                raise Exception("No suitable browser found")
 
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

# url_testlist = ["https://demo.testfire.net/search.jsp?query=test", "https://demo.testfire.net/default.jsp?content=test"
#                 "https://demo.testfire.net/index.jsp?content=test", "https://demo.testfire.net/util/serverStatusCheckService.jsp?Hostname=test"] # TEST ON TESTFIRE
url_testlist = []

# get the URLs that are GET requests as well as the URLs and have a parameter to inject
with open("crawl.txt", "r") as crawl_file: # change this back to crawl.txt after the testing
    for i in crawl_file.readlines():
        data_dict = json.loads(i)
        if data_dict["Method"] == "GET":
            if "?" in data_dict["URL"]:
                url_testlist.append(data_dict["URL"])

error_xml_file = 'scripts/errors.xml'
sqlpayloadfile='sqlpayload.txt'
text_file = open(sqlpayloadfile, "r")
sql_payload_list = text_file.read().split('\n')

xsspayloadfile='xsspayload.txt'
text_file = open(xsspayloadfile, "r")
xss_payload_list = text_file.read().split('\n')

sql_vuln_file = 'injection-results/sql_vuln_endpoints.txt'
xss_vuln_file = 'injection-results/xss_vuln_endpoints.txt'
ssrf_vuln_file = 'injection-results/ssrf_vuln_endpoints.txt'

if 'chms' in url : 
    # login using requests
    session_cookie = login_get_cookie_jar(url, username, password)
    # session_cookie = requests_login(username,password)
    if session_cookie == - 1 :
        print("Incorrect Credentials")
        sys.exit()

    # login using selenium web driver
    driver = create_webdriver() 
    browser = selenium_login(driver, url, username, password)
else :
    browser = create_webdriver()
    session_cookie = ""
# session_cookie = cookies = {
#     'PHPSESSID': '201d7e8410a03beb3409f600ce14bea6',
#     'security_level': '0',
#     # Add more cookies as needed
# } # This cookie is to test for the bee-box

if int(scan_for_sql) == 1 :
    affected_urls_list = sql_tryauto(url_testlist,session_cookie,sql_payload_list,error_xml_file)
    with open(sql_vuln_file,"a+") as file:
        file.writelines(str(row) +'\n' for row in affected_urls_list)
    print("Done with SQL injection - AUTO\n")

if int(scan_for_xss) == 1 :
    affected_urls_list = xss_tryauto(url_testlist, browser, xss_payload_list)
    with open(xss_vuln_file,"a+") as file:
        file.writelines(str(row) +'\n' for row in affected_urls_list)
    print("Done with xss injection - AUTO\n")

if int(scan_for_ssrf) == 1 :
    ### generating the token for the webhook
    resp = requests.post("https://webhook.site/token")
    token1 = json.loads(resp.text)["uuid"]

    vulnerabilitylist = tryssrf(url_testlist, token1, session_cookie)
    ssrfWeak = False
    if len(vulnerabilitylist["internal"]) > 0 or len(vulnerabilitylist["external"]) > 0:
        ssrfWeak = True

    # 4th is involving in sending the SQL to the database
    if ssrfWeak:
        db_host = config.get("SQL Database", "db_host")
        db_user = config.get("SQL Database", "db_user")
        db_password = config.get("SQL Database", "db_password")
        db_connection = mysql.connector.connect(
            host=db_host, user=db_user, password=db_password, database="vulnerabilities"
        )

        db_cursor = db_connection.cursor()
        cwe_id = "CWE-918"
        # Insert a row into the MySQL table
        vuln_yml = vuln_extract(cwe_id)
        name = vuln_yml["name"]
        vulnerabilitylist_json = json.dumps(vulnerabilitylist)
        insert_query = "INSERT INTO vulnerabilities (scan_id, vulnerability_name, vulnerability_id, url, additional_information) VALUES (%s, %s, %s, %s, %s)"
        values = []
        values.append([scan_id, name, cwe_id, user_input, vulnerabilitylist_json])
        print(values)
        db_cursor.executemany(insert_query, values)  # Insert multiple rows together
        db_connection.commit()
        db_cursor.close()
        db_connection.close()

if int(sql_inject_all_eps) == 1 or int(xss_inject_all_eps) ==  1 or int(ssrf_inject_all_eps): # only run the browserlaunch.py if user checks inject all eps
    process = subprocess.Popen(['python', f"./scripts/BrowserLaunch.py", url, str(scan_id)])
    process.wait() # wait for process to finish

else : # if browserlaunch.py will not be run, the write vuln ep to db
    with open(sql_vuln_file, 'r') as file :
        sql_affected_urls = file.readlines()
        sql_affected_urls = [affected for affected in sql_affected_urls if affected != ""]

    with open(xss_vuln_file, 'r') as file :
        xss_affected_urls = file.readlines()
        xss_affected_urls = [affected for affected in xss_affected_urls if affected != ""]

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