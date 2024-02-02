import requests
import configparser
import subprocess
import json
import mysql.connector
import time
import sys
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
filename = config.get('Advanced Scan Settings', 'mapped_file')
idor_user1 = config.get('Advanced Scan Settings', 'idor_user1')
user1_pwd = config.get('Advanced Scan Settings', 'user1_password')
idor_user2 = config.get('Advanced Scan Settings', 'idor_user2')
user2_pwd = config.get('Advanced Scan Settings', 'user2_password')
idor = config.get('Advanced Scan Settings','scan_for_insecure_direct_object_references')

if int(idor) == 1 :

    # check if user1 and user2 creds are correct
    cookie_user1 = login_get_cookie_jar(url, idor_user1, user1_pwd)
    cookie_user2 = login_get_cookie_jar(url, idor_user2, user2_pwd)
    
    # # TEST ON SELF DESIGN SITE
    # from seleniumBot import test_login_get_cookie_jar
    # cookie_user1 = test_login_get_cookie_jar(url, idor_user1, user1_pwd)
    # cookie_user2 = test_login_get_cookie_jar(url, idor_user2, user2_pwd)

    if cookie_user1 == -1 or cookie_user2 == -1 :
        print("IDOR Users's credentials are incorrect.")
        sys.exit()
    
    print(f"{idor_user1}\nCreds Successful")
    print(f"{idor_user2}\nCreds Successful\n")

    user1_dict = {
        "loginid" : idor_user1,
        "password" : user1_pwd
    }
    user2_dict = {
        "loginid" : idor_user2,
        "password" : user2_pwd
    }
    users = [user1_dict, user2_dict]

    for user in users :
        # for loginid, password in user.items() :
        # change value in config.ini
        config.set('Advanced Scan Settings', 'scraping_username', user['loginid'])
        config.set('Advanced Scan Settings', 'scraping_password', user['password'])
        config.set('Advanced Scan Settings', 'mapped_file', f'crawl-{user["loginid"]}.txt')
        with open('config.ini', 'w') as configfile:
            config.write(configfile)

        user['filename'] = f"crawl-{user['loginid']}.txt"

        # start crawling
        script_path = "scripts/crawler.py"
        script_arguments = [url, str(scan_id)] # args can be removed once test suite is completed

        # Use subprocess to run the script
        process = subprocess.Popen(["python", script_path] + script_arguments, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        print(f"Crawling - {user['loginid']}")
        # Wait for the process to finish and capture the output
        stdout, stderr = process.communicate()

        # # Print the output and error, if any
        print("Script Output:", stdout.decode())
        print("Script Error:", stderr.decode())

        # Get the return code of the process
        return_code = process.returncode
        print("Return Code:", return_code)

    # set back to initial value
    config.set('Advanced Scan Settings', 'scraping_username', username)
    config.set('Advanced Scan Settings', 'scraping_password', password)
    config.set('Advanced Scan Settings', 'mapped_file', filename)
    with open('config.ini', 'w') as configfile:
        config.write(configfile)

    # testing for idor
    url_list1 = []
    with open(users[0]['filename'],'r') as crawl_file:
        for i in (crawl_file.readlines()):
            data_dict = json.loads(i) #Data is now a dictionary from json loads
            #To get parent url
            if data_dict['Method'] == "GET" :
                url_list1.append(data_dict['URL'])

    url_list2 = []
    with open(users[1]['filename'],'r') as crawl_file:
        for i in (crawl_file.readlines()):
            data_dict = json.loads(i) #Data is now a dictionary from json loads
            #To get parent url
            if data_dict['Method'] == "GET" :
                url_list2.append(data_dict['URL'])
    
    # remove contents in file
    with open(f'crawl-{user1_dict["loginid"]}.txt', 'w'):
        pass 
    with open(f'crawl-{user2_dict["loginid"]}.txt', 'w'):
        pass
 
    set1 = set(url_list1)
    set2 = set(url_list2)
    user1_unique_url = list(set1 - set2)
    user2_unique_url = list(set2 - set1)

    print(f"num of user1 objects - {len(user1_unique_url)}")
    print(f"num of user2 objects - {len(user2_unique_url)}")

    urltoaccess_list = []
    if len(user1_unique_url) == len(user2_unique_url) :
        # use user1 to access user2 object
        cookie = cookie_user1
        # cookie = login(users[0]['loginid'], users[0]['password'])
        urltoaccess_list = user2_unique_url
        user_that_performed_attack = user1_dict['loginid']
    
    else :
        if len(user1_unique_url) > len(user2_unique_url) :
            # user1 has more objects than user2 may be because user1 has perm to more modules / more objects
            # use user1 to access user2 object
            cookie = cookie_user1
            # cookie = login(users[0]['loginid'], users[0]['password'])
            urltoaccess_list = user2_unique_url
            user_that_performed_attack = user1_dict['loginid']
        else :
            # user2 has more objects than user1 may be because user1 has perm to more modules / more objects
            # use user2 to access user1 object
            cookie = cookie_user2
            # cookie = login(users[1]['loginid'], users[1]['password'])
            urltoaccess_list = user1_unique_url
            user_that_performed_attack = user2_dict['loginid']

    affected_urls = []
    for url in urltoaccess_list :
        response = requests.get(url, cookies=cookie)
        time.sleep(5)
        if response.status_code == 403 : # remove 404 later
            print(url + " : " + response.reason)
        
        elif response.status_code == 200 :
            affected_urls.append(url)
            print(url + ": accessible")

        else :
            print(f"Status Code : {response.status_code} {response.reason}")
            sys.exit()
    
    if len(affected_urls) > 0 :
        print("Website is vulnerable to IDOR")
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
        cwe_id = "CWE-639"
        # Insert a row into the MySQL table
        vuln_yml = vuln_extract(cwe_id)
        name = vuln_yml["name"]

        insert_query = "INSERT INTO vulnerabilities (scan_id, vulnerability_name, vulnerability_id, url, additional_information) VALUES (%s, %s, %s, %s, %s)"
        values = []
        affected_urls_dict = {
            "user" : user_that_performed_attack,
            "urls":affected_urls
        }
        affected_urls_dict_json = json.dumps(affected_urls_dict)
        # for url in affected_urls :
        values.append([scan_id,name,cwe_id,user_input,affected_urls_dict_json])
        db_cursor.executemany(insert_query, values)# Insert multiple rows together
        db_connection.commit()

        db_cursor.close()
        db_connection.close()

