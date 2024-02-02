import requests
import mysql.connector
import sys
import configparser
import json
from urllib.parse import urlparse
from os.path import dirname
sys.path.append(dirname(dirname(f'{__file__}')))
from v2.yaml_vuln import vuln_extract
from seleniumBot import login_get_cookie_jar
from fake_useragent import UserAgent


if __name__ == "__main__":
    user_input = sys.argv[1] # this is the domain
    scan_id = int(sys.argv[2])

parsed_url = urlparse(user_input)
scheme = parsed_url.scheme
netloc = parsed_url.netloc
url = scheme + "://" + netloc

# retrieve info from config.ini
config = configparser.ConfigParser()
config.read("config.ini")
username = config.get('Advanced Scan Settings','scraping_username')
password = config.get('Advanced Scan Settings','scraping_password')
session_hijacking = config.get('Advanced Scan Settings','scan_for_session_hijacking')

if int(session_hijacking) == 1 :
    uses_hsts = False
    sessionHijacking = True
    try :
        response = requests.get(url)
        hsts_header = response.headers.get('Strict-Transport-Security', None)

        if hsts_header :
            uses_hsts = True
            print(f"{url} is using HSTS. HSTS Header: {hsts_header}")
    
    except requests.exceptions.RequestException as e:
        print(e)
        sys.exit()

    # check if another user-agent can hijack a session 
    ua = UserAgent()
    user_agent = ua.random
    cookie = login_get_cookie_jar(url, username, password)

    # # TEST ON DEMO.TESTFIRE.NET
    # from seleniumBot import test_login_get_cookie_jar
    # cookie = test_login_get_cookie_jar(url, username, password)

    headers = {'User-Agent' : user_agent}
    response = requests.get(url, headers=headers, cookies=cookie)
    # response = requests.get(url + "/bank/main.jsp", headers=headers, cookies=cookie) # TEST ON TESTFIRE
    print(response.request.headers)
    login_url = url + "/login"
    # login_url = url + "/login.jsp" # TEST ON TESTFIRE
    if response.url == login_url :
        print("Cookie is prevented from usage from another User Agent.")
        sessionHijacking = False

    ###################### WRITING AFFECTED URLS/ENDPOINTS TO DB #################
    if not uses_hsts or sessionHijacking :
        if not uses_hsts :
            test_result = "Website is not using HSTS header and is potentially vulnerable to session hijacking when session cookie is transmitted over HTTP."
        else :
            test_result = "Website uses HSTS but cookie can still be stolen through other means to hijack the session."
        if (not uses_hsts) and session_hijacking :
            test_result = "Website is not using HSTS header and session can be hijacked."
        print(test_result)

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
        cwe_id = "CAPEC-593"
        # Insert a row into the MySQL table
        vuln_yml = vuln_extract(cwe_id)
        name = vuln_yml["name"]
        test_result_dict = {
            "results" : test_result
        }
        test_result_json = json.dumps(test_result_dict)
        insert_query = "INSERT INTO vulnerabilities (scan_id, vulnerability_name, vulnerability_id, url, additional_information) VALUES (%s, %s, %s, %s, %s)"
        values = []
        values.append([scan_id,name,cwe_id,url,test_result_json])
        db_cursor.executemany(insert_query, values)# Insert multiple rows together
        db_connection.commit()

        db_cursor.close()
        db_connection.close()


