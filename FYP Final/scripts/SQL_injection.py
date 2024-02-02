import sys
import requests
import json
from os.path import dirname
sys.path.append(dirname(dirname(f'{__file__}')))
from scripts.sql_errors import sql_error_check
from datetime import timedelta
from timeit import default_timer as timer
from time import sleep
from seleniumBot import login_get_cookie_jar

def sql_tryauto(listofgeturlrequests,session_cookie,payload_list,error_xml_file):
    affected_urls = []
    trylist_sql = set()
    # for every url:
    for url in listofgeturlrequests:
        def makeinject(url,payload):
            querysplit = url.split("?")
            anpersplit = querysplit[1].split("&")
            newlist = []
            for i in anpersplit:
                valusplit = i.split("=")
                querystring = f"{valusplit[0]}={payload}"
                newlist.append(querystring)
            addanper = "&".join(newlist)
            addquery = f"{querysplit[0]}?{addanper}"
            return addquery
        # add a payload
        for payload in payload_list:
            addquery = makeinject(url,payload)
            trylist_sql.add(addquery)
    # start testing now:
    for injection_url in trylist_sql:
        print(f"trying: {injection_url}")
        start = timer()
        resp_in_text = requests.get(injection_url,cookies=session_cookie).text
        end = timer()
        delay_time_s = 120
        error = sql_error_check(resp_in_text, error_xml_file)
        if error != -1 :
            vuln_endpoint = {"Endpoint" : injection_url, "Payload" : "", "Error" : error}
            print("error found")
            affected_urls.append(vuln_endpoint)
        elif (timedelta(seconds=4.9) <= timedelta(seconds=end - start) <= timedelta(seconds=delay_time_s)):
            vuln_endpoint = {"Endpoint" : injection_url, "Payload" : "", "Error" : "There was a delay in the load time. Possible error"}
            print("Delay error found")
            affected_urls.append(vuln_endpoint)
    
    return affected_urls

def sql_injection(baseurl, endpoint, method, params) : # params - input field's id in dict

    if endpoint == baseurl + "/authenticate" :
        session_cookie = login_get_cookie_jar(baseurl, params['loginId'], params['password'])
        # response = requests.post(endpoint, data=params)
        # session_cookie = response.cookies
        if session_cookie != -1 :
            cookie_storage.append(session_cookie)

    # print(f"Injecting into : {endpoint}")
    for payload in sql_payload_list :
        for key in params.keys() :
            params[key] = payload
        print(f"Payload injected into {endpoint}\n{params}")
        
        delay_time_s = 5
        time_based_keyword = ["SLEEP", "DELAY", "WAIT", str(delay_time_s)]
        if any(keyword in payload for keyword in time_based_keyword) : # inject time base payload
            start = timer()
            if cookie_storage :
                response = method(endpoint, data=params, cookies=cookie_storage[0])
                # response = requests.post(endpoint, data=params, cookies=cookie_storage[0])
            else :
                response = method(endpoint, data=params)
                # response = requests.post(endpoint, data=params)
            end = timer()

            if timedelta(seconds=end - start) >= timedelta(seconds=delay_time_s) :
                print("Time Based SQLi worked")
                vuln_endpoint = {'Endpoint' : endpoint, 'Payload' : payload, "Error" : f"Response time was delayed for {delay_time_s} seconds."}
                with open(sql_vuln_file, 'a') as file :
                    file.write(json.dumps(vuln_endpoint) + '\n')
                # sql_affected_urls.append(vuln_endpoint) # write to sql vuln file
                break # end loop if detected blind sqli

        else : # inject not paylods that is not time based
            if cookie_storage :
                response = method(endpoint, data=params, cookies=cookie_storage[0])
                # response = requests.post(endpoint, data=params, cookies=cookie_storage[0])
            else :
                response = method(endpoint, data=params)
                # response = requests.post(endpoint, data=params)
        sleep(1)

        # check whether app is vuln to sqli
        error = sql_error_check(response.text, error_xml_file)
        if error != -1 :
            vuln_endpoint = {"Endpoint" : endpoint, "Payload" : payload, "Error" : error}
            with open(sql_vuln_file, 'a') as file :
                file.write(json.dumps(vuln_endpoint) + '\n')
            # sql_affected_urls.append(vuln_endpoint) # write to sql vuln file
            break
        else :
            if response.status_code == 500 :
                error = f"{response.reason} - {response.status_code}"
                # input(response.text)
                vuln_endpoint = {"Endpoint" : endpoint, "Payload" : payload, "Error" : error}
                with open(sql_vuln_file, 'a') as file :
                    file.write(json.dumps(vuln_endpoint) + '\n')
                # sql_affected_urls.append(vuln_endpoint) # write to sql vuln file
                break
    
    print("Done injecting...")
    print(f"Errors : {error}\n")

cookie_storage = []
error_xml_file = 'scripts/errors.xml'
sql_vuln_file = 'injection-results/sql_vuln_endpoints.txt'

# put sql payloads into list
sql_payloadfile='sqlpayload.txt'
text_file = open(sql_payloadfile, "r")
sql_payload_list = text_file.read().split('\n')
text_file.close()