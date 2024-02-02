import requests
import mysql.connector
import sys
import configparser
import json
from os.path import dirname
from urllib.parse import urlparse
sys.path.append(dirname(dirname(f'{__file__}')))
from v2.yaml_vuln import vuln_extract
from seleniumBot import login_get_cookie_jar


# def login(username, password) :
#     login_info = {"loginId":username, "password":password}
#     response = requests.post("https://chmsdemo.greenfossil.com/authenticate", data=login_info)
#     session_cookie = response.cookies
#     return session_cookie

def replace_cookie_value(cookies, new_value) :

    for cookie in cookies :
        if cookie.name == "APP_SESSION" :
            cookie.value = new_value

    return cookies

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
session_fixation = config.get('Advanced Scan Settings','scan_for_session_fixation')

if int(session_fixation) == 1 :
    session_fixation = {"result" : True}

    # # TESTING ON DEMO.TESTFIRE.NET
    # response = requests.get(url)
    # cookie_name = "JSESSIONID"
    # session_identifier = response.cookies[cookie_name]
    # #login get session cookie
    # from seleniumBot import test_login_get_cookie_jar
    # session_cookie = test_login_get_cookie_jar(url, username, password)

    # Browse to website to get a session identifier
    response = requests.get(url)
    session_identifier = response.request.headers['COOKIE'].split("APP_SESSION=")[1]

    ### login first to get APP_SESSION cookie ###
    session_cookie = login_get_cookie_jar(url, username, password)

    if session_cookie == -1 :
        print("Username/Password incorrect.")
        sys.exit()
        
    print(f"{session_cookie}\nLogin Successful\n")
    
    returned_cookie = session_cookie["APP_SESSION"] # application returns new/protected session identifier
    # returned_cookie = session_cookie # TEST ON TESTFIRE

    if session_identifier != returned_cookie :
        # there is no session fixation
        session_fixation['result'] = False
        print("New session token is returned.")
        print(f"Initial cookie : {session_identifier}")
        print(f"New cookie : {returned_cookie}\n")

        # IN CASE, check if the initial session identifier can be used as an authenicated user
        session_identifier = replace_cookie_value(session_cookie, session_identifier) # fn is to put cookie in cookie jar format
        response = requests.get(url, cookies=session_identifier)
        print(f"Browsing {url} using initial cookie...\nRedirected: {response.url}")
        # print(response.cookies)
        if response.url == url + "/login" :
        # if response.url == url + "/login.jsp" : # TEST ON TESTFIRE
            session_fixation['result'] = False
            print(f"Initial Session Identifier cannot be reused.")
            print(f"{session_identifier} : invalid")

        else : # if it does not redirects to login page --> cookie is valid
            session_fixation['result'] = True
            session_fixation['poc'] = "Session identifier before login can be used to access website"
            print("There is Session Fixation")

    else : # check if it is a valid session identifier
        session_identifier = replace_cookie_value(session_cookie, session_identifier) # fn is to put cookie in cookie jar format
        response = requests.get(url, cookies=session_identifier)
        print(f"Browsing {url} using initial cookie...\nRedirected: {response.url}")
        
        if response.url == url + "/login" :
        # if response.url == url + "/login.jsp" : # TEST ON TESTFIRE
            session_fixation['result'] = False
            print("Session identifier is invalid")

        else : # if it does not redirects to login page --> cookie is valid
            session_fixation['result'] = True
            session_fixation['poc'] = "Session cookie returned after login is the same as session identifier before login"
            print("There is Session Fixation")

    ###################### WRITING AFFECTED URLS/ENDPOINTS TO DB #################
    if session_fixation['result'] :
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
        cwe_id = "CWE-384"
        # Insert a row into the MySQL table
        vuln_yml = vuln_extract(cwe_id)
        name = vuln_yml["name"]
        session_fixation_json = session_fixation
        results = json.dumps(session_fixation_json)

        insert_query = "INSERT INTO vulnerabilities (scan_id, vulnerability_name, vulnerability_id, url, additional_information) VALUES (%s, %s, %s, %s, %s)"
        values = []
        values.append([scan_id, name, cwe_id, url, results])
        db_cursor.executemany(insert_query, values)# Insert multiple rows together
        db_connection.commit()

        db_cursor.close()
        db_connection.close()
        