import requests
import json
import sys
import configparser
import mysql.connector
import json
from urllib.parse import urlparse
from os.path import dirname
sys.path.append(dirname(dirname(f'{__file__}')))
from v2.yaml_vuln import vuln_extract
from seleniumBot import login_get_cookie_jar

if __name__ == "__main__":
    user_input = sys.argv[1]
    scan_id = int(sys.argv[2])

parsed_url = urlparse(user_input)
scheme = parsed_url.scheme
netloc = parsed_url.netloc
base_url = scheme + "://" + netloc

# def login(username,password):
#     login_info = {"loginId":f"{username}", "password":f"{password}"} # REMEMBER TO CHANGE HARDCODED LOGINID AND PASSWORD
#     response = requests.post("https://chmsdemo.greenfossil.com/authenticate", data=login_info)
#     return response.cookies

# retrieve info from config.ini
config = configparser.ConfigParser()
config.read("config.ini")
username = config.get('Advanced Scan Settings','scraping_username')
password = config.get('Advanced Scan Settings','scraping_password')
allowed_http_methods = config.get('Advanced Scan Settings','scan_for_allowed_http_methods')


if int(allowed_http_methods) == 1 or True :
     #### login first to get APP_SESSION cookie - CAN REPLACE TO EXTRACT FROM PICKLE FILE #### 
    session_cookie = login_get_cookie_jar(base_url, username, password)
    # session_cookie = login(username,password)
    
    if session_cookie == -1 :
        print("Username/Password incorrect.")
        sys.exit()

    urls = {}
    with open('crawl.txt','r') as jsonfile:
        for i in jsonfile.readlines():
            data_dict = json.loads(i)
            if(data_dict['Endpoint'] not in ["",None]):
                #There is something for the endpoint
                if(data_dict['Endpoint'] in urls.keys()):
                    #Endpoint already exists
                    #Check if method is the same
                    if(data_dict['Method'] not in urls[data_dict['Endpoint']]):
                        urls[data_dict['Endpoint']].append(data_dict['Method'])
                    continue
                urls[data_dict['Endpoint']]=[data_dict["Method"]]

    HTTP_METHODS = (requests.get, requests.post, requests.put, requests.delete, requests.options, requests.patch)

    # send request to each url using all http methods
    affected_urls = []
    for key in urls.keys():
        print(key)
        methods_allowed = []
        methods_not_allowed = []

        for method in HTTP_METHODS :
            response = method(base_url + key, cookies=session_cookie)
            if(key == '/logout'):
                session_cookie = login_get_cookie_jar(base_url, username, password)
                # session_cookie = login(username,password)#Reset session cookie
            if response.status_code == 405:
                methods_not_allowed.append((method.__name__).upper())
            else :
                methods_allowed.append((method.__name__).upper())
        print(f"Method set to be allowed: {','.join(urls[key]).upper()}")
        print(f"Methods allowed: {','.join(methods_allowed)}")        
        print(f"Methods not allowed: {','.join(methods_not_allowed)}")

        method_that_should_not_be_allowed = []
        for method in methods_allowed :
            # check if allowed method is supposed to be allowed
            if method.casefold() not in [method.casefold() for method in urls[key]]: # url[1] is the expected/allowed method
                method_that_should_not_be_allowed.append(method)
                # print(f"{endpoint} allowed methods that it should not.")

        if len(method_that_should_not_be_allowed) > 0 :
            affected_urls.append([base_url+key, method_that_should_not_be_allowed])
        # new line
        print()

    print("AFFECTED URLs:")
    for url in affected_urls :
        affectedinfo = f"{url[0]} - Methods that should not be allowed: {','.join(url[1])} "
        print(affectedinfo)

    if len(affected_urls) > 0 :
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
        cwe_id = "CWE-650"
        # Insert a row into the MySQL table
        vuln_yml = vuln_extract(cwe_id)
        name = vuln_yml["name"]

        insert_query = "INSERT INTO vulnerabilities (scan_id, vulnerability_name, vulnerability_id, url, additional_information) VALUES (%s, %s, %s, %s, %s)"
        values = []
        vulnerable_dict = {}
        for url in affected_urls:
            vulnerable_dict[url[0]]=url[1]
            # values.append([scan_id,name,cwe_id,url[0],f"Methods not allowed:{','.join(url[1])}"])
        vulnerable_dict_json = json.dumps(vulnerable_dict)
        values.append([scan_id,name,cwe_id,base_url,vulnerable_dict_json])
        db_cursor.executemany(insert_query, values)# Insert multiple rows together
        db_connection.commit()

        db_cursor.close()
        db_connection.close()