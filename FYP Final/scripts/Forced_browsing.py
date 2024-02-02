import requests
import configparser
import mysql.connector
import sys
from os.path import dirname
sys.path.append(dirname(dirname(f'{__file__}')))
from v2.yaml_vuln import vuln_extract
from urllib.parse import urlparse
import json
import re
from urllib.parse import unquote
import time
from seleniumBot import login_get_cookie_jar

if __name__ == "__main__":
    user_input = sys.argv[1]
    scan_id = sys.argv[2]

parsed_url = urlparse(user_input)
scheme = parsed_url.scheme
netloc = parsed_url.netloc
url = scheme + "://" + netloc

directory_forceable = []
config = configparser.ConfigParser()
config.read("config.ini")
username = config.get('Advanced Scan Settings','scraping_username')
password = config.get('Advanced Scan Settings','scraping_password')
force_browse = config.get('Advanced Scan Settings','scan_for_forced_browsing')
wordlist = config.get('Advanced Scan Settings','directory_wordlists')

# def login(username,password):
#     login_info = {"loginId":f"{username}", "password":f"{password}"} # REMEMBER TO CHANGE HARDCODED LOGINID AND PASSWORD
#     response = requests.post("https://chmsdemo.greenfossil.com/authenticate", data=login_info)
#     return response.cookies

def crawl_directory(base_url, new_list, cookie):
    directory_force = []
    for word in new_list:
        url = f"{base_url}{word}"
        response = requests.get(url,cookies=cookie)
        print(f'i am getting this url: ${url}')
        if response.status_code == 200:
            directory_force.append(url)

    return directory_force


def wordlist_function():
    if wordlist == "1k":
        myfile = open('scripts/1k_wordlist.txt','r')
    elif wordlist == "10k":
        myfile = open('scripts/10k_wordlist.txt','r')
    elif wordlist == "36k":
        myfile = open('scripts/36k_wordlist.txt','r') 
    newlist = []
    for line in myfile:
        line = '/'+ line
        newlist.append(line.replace("\n",""))
    return(newlist)

def number_increment(cookie):
    '''
    Attempt to increment a number within the directory
    http://example.com/user1 -> http://example.com/user2
    
    Check if such url already exist within the crawl file.
    Increment the number if already exist.
    If not try and access and see if 200 was returned
    '''
    url_with_num = []
    with open('crawl.txt') as file:
         for i in (file.readlines()):
            data_dict = json.loads(i) #Data is now a dictionary from json loads
            #Examples to read data
            #To print all fields
            method = data_dict['Method']
            url = unquote(data_dict['URL'])
            actual_url = url
            if '?' in url:
                actual_url = url.split("?")[0]
            if method != None and method.upper() == "GET" and any(s.isdigit()  for s in actual_url):# Check if url has a digit and ignore all url with query string
                url_with_num.append(url)
    #Filtering for url to prevent repeated & selecting the highest number
    url_top_dict = {}
    for url in url_with_num:
        query=""
        if "?" in url:
            split_url = url.split('?')
            url = split_url[0]
            query = split_url[1]
        regex_val = re.finditer("[0-9]+",url)
        for m in regex_val:
            start, end = m.span()
            value = int(m.group())+1
            first_part = url[:start]
            second_part = url[end:] if query == "" else url[end:]+"?"+query
            if first_part not in url_top_dict.keys():
                url_top_dict[first_part]={value:{second_part,}}
            else:
                #Compare
                value_dict = url_top_dict[first_part]
                if list(value_dict.keys())[0] < value:
                    key = list(value_dict.keys())[0]
                    arr = value_dict[key]
                    arr.add(second_part)
                    url_top_dict[first_part][value] = arr
                    del url_top_dict[first_part][key]
    # Combining the urls
    all_urls = []                
    for key,value in url_top_dict.items():
        number = list(value.keys())[0]
        for second_part in value[number]:
            all_urls.append(f"{key}{number}{second_part}")
    #Now that all the potential forceable urls are created, send the requests and check for valid responses (200)
    forceable = []
    for url in all_urls:
        resp = requests.get(url,cookies=cookie)
        if(resp.status_code == 200):
            forceable.append(url)
        time.sleep(1)

    return forceable


if int(force_browse) == 1:
    cookie = login_get_cookie_jar(url, username, password)
    # cookie = login(username,password) #Recommended to use regular user, need to check if login is successful
    status = False
    for cook in cookie:
        if(cook.name =="APP_SESSION"):
            status=True
    if not status:
        print("Login Failed")
        exit(1)
    directory_force_1 = number_increment(cookie)
    print(directory_force_1)
    word_list = wordlist_function()
    base_url = user_input
    directory_force_2 = crawl_directory(base_url,word_list,cookie)
    directory_force = directory_force_1 + directory_force_2
    if directory_force is not None:
        config = configparser.ConfigParser()
        config.read("config.ini")
        # Get values from the config file
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
        cwe_id = "CWE-425"
        # Insert a row into the MySQL table
        vuln_yml = vuln_extract(cwe_id)
        name = vuln_yml["name"]

        insert_query = "INSERT INTO vulnerabilities (scan_id, vulnerability_name, vulnerability_id, url, additional_information) VALUES (%s, %s, %s, %s, %s)"
        values = []
        directory_force_dict = {
            "url":directory_force
        }
        directory_force_dict_json = json.dumps(directory_force_dict)
        # for url in directory_force:
        values.append([scan_id,name,cwe_id,base_url,directory_force_dict_json])
        db_cursor.executemany(insert_query, values)# Insert multiple rows together
        db_connection.commit()

        db_cursor.close()
        db_connection.close()
        print('there is an directory force error')
        print(f"this is the list of urls with pages that can be directory-forced: ${str(directory_force)}")
    else:
        print('there is no directory force error')
