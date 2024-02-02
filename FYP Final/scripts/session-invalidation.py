import requests
import json
import mysql.connector
import sys
import configparser
from urllib.parse import urlparse
from os.path import dirname
sys.path.append(dirname(dirname(f'{__file__}')))
from v2.yaml_vuln import vuln_extract
from seleniumBot import login_get_cookie_jar

# def login(username, password) :
#     login_info = {"loginId":username, "password":password}
#     response = requests.post("https://chmsdemo.greenfossil.com/authenticate", data=login_info)
#     session_cookie = response.cookies
#     return session_cookie


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
session_invalidation = config.get('Advanced Scan Settings','scan_for_session_invalidation')

if int(session_invalidation) == 1 :
    weak_session_mgmt = True
    #### login first to get APP_SESSION cookie #### 
    session_cookie = login_get_cookie_jar(url, username, password)
    
    # # TEST ON SELF DESIGN TEST SITE 
    # from seleniumBot import test_login_get_cookie_jar
    # session_cookie = test_login_get_cookie_jar(url, username, password)

    if session_cookie == -1 :
        print("Username/Password incorrect.")
        sys.exit()

    print(f"{session_cookie}\nLogin Successful\n")
    
    # Logout
    response = requests.get(url + "/logout", cookies=session_cookie)
    print("Logged out\n")

    # Access website using above session cookie
    response = requests.get(url, cookies=session_cookie)
    print(f"Browsing {url}\nRedirected: {response.url}")

    if response.url == url + "/login" : # if session cookie is invalid, it will redirect back to login
        weak_session_mgmt = False
        print(f"{session_cookie} : invalid")
        print("Session cookie cannot be reused after logout.")
    else :
        weak_session_mgmt = True

    ###################### WRITING AFFECTED URLS/ENDPOINTS TO DB #################
    if weak_session_mgmt :
        print("Session cookie can be reused.")
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
        cwe_id = "CWE-613"
        # Insert a row into the MySQL table
        vuln_yml = vuln_extract(cwe_id)
        name = vuln_yml["name"]
        results_json = {
            "results" : "Session cookie could be reused even after logging out."
        }
        results = json.dumps(results_json)
        insert_query = "INSERT INTO vulnerabilities (scan_id, vulnerability_name, vulnerability_id, url, additional_information) VALUES (%s, %s, %s, %s, %s)"
        values = []
        values.append([scan_id,name,cwe_id,url,results])
        db_cursor.executemany(insert_query, values)# Insert multiple rows together
        db_connection.commit()

        db_cursor.close()
        db_connection.close()
        