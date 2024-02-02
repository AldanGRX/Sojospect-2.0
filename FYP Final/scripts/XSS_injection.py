import json
from urllib.parse import urlparse
from time import sleep
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.by import By 
from selenium.webdriver.common.keys import Keys
from seleniumwire import webdriver
from seleniumBot import login_get_cookie_jar

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

def selenium_login(driver, url, username, password): # login using selenium
    login_url = url + '/login'
    driver.get(login_url)
    driver.find_element(By.ID, 'loginId').send_keys(username) # double check login id and password id fields
    driver.find_element(By.ID, 'password').send_keys(password, Keys.RETURN)
    sleep(5)
    return driver

def __xss_attribute_check(body,payload_value):

    if payload_value in body :
        return True
    return False

def __xss_triggered_check(url, browser):
    browser.get(url)
    try:
        WebDriverWait(browser, 3).until(EC.alert_is_present(),'Timed out')
        alert = browser.switch_to.alert
        alert.accept()
        return True
    except:
        return False

def xss_tryauto(listofgeturlrequests, browser, payload_list) :
    affected_urls = []
    xss = False
    for url in listofgeturlrequests :
        parsed_endpoint = urlparse(url)
        base_url = parsed_endpoint[0] + "://" + parsed_endpoint[1] + parsed_endpoint[2]
        queries = parsed_endpoint.query # replace query value with payload value later on 
        # e.g. queries : q1=input1&q2=input2
        queries_list = queries.split('&')
        # e.g. ["q1=input1", "q2=input2"]
        for query in queries_list :
            injected_queries = query.split('=')[0] + "="
        injected_url = base_url + "?" + injected_queries
        
        for payload in payload_list :
            url_to_send = base_url + '?'
            modified_queries = []
            for query in queries_list :
                modified_query = query.split('=')[0] + '=' + payload
                modified_queries.append(modified_query)
            
            modified_queries = '&'.join(modified_queries)
            url_to_send += modified_queries
            print(f"trying: {url_to_send}")

            rxss = __xss_triggered_check(url_to_send, browser) # check if alert pops up on browser
            if not rxss : # if no alert pops up, check if there is proper validation/sanitization
                xss = __xss_attribute_check(browser.page_source, payload)

            if rxss or xss :
                vuln_endpoint = {"Endpoint" : injected_url, "Payload" : payload}
                affected_urls.append(json.dumps(vuln_endpoint))
                break # if endpoint vulnerable skip all other payloads
    
    return affected_urls

def xss_injection(baseurl, endpoint, method, params) : # params - input field's id in dict

    if endpoint == baseurl + "/authenticate" :
        session_cookie = login_get_cookie_jar(baseurl, params['loginId'], params['password'])
        # response = requests.post(endpoint, data=params)
        if session_cookie != -1 :
            cookie_storage.append(session_cookie)

            # selenium login
            driver = create_webdriver()
            browser = selenium_login(driver, baseurl, params['loginId'], params['password']) 
    else :
        browser = create_webdriver()

    print(f"Injecting into : {endpoint}")
    
    # Injecting into POST/PUT req
    for payload in xss_payload_list :
        for key in params.keys() :
            params[key] = payload

        if cookie_storage :
            response = method(endpoint, data=params, cookies=cookie_storage[0])
            # response = requests.post(endpoint, data=params, cookies=cookie_storage[0])
        else :
            response = method(endpoint, data=params)
            # response = requests.post(endpoint, data=params)
        sleep(1)
        print(f"Payload injected into {endpoint}\n{params}")
        
        xss = __xss_attribute_check(response.text, payload) # check if there is input validation/sanitization
        if xss :
            vuln_endpoint = {"Endpoint" : endpoint, "Payload" : payload}
            with open(xss_vuln_file, 'a') as file :
                file.write(json.dumps(vuln_endpoint) + '\n')
            # affected_urls.append(vuln_endpoint) # write vuln endpoint into file
            break
    print("Done injecting...\n")


cookie_storage = []
xss_vuln_file = 'injection-results/xss_vuln_endpoints.txt'
xss_payloadfile ='xsspayload.txt'
text_file = open(xss_payloadfile, "r")
xss_payload_list = text_file.read().split('\n')
text_file.close()