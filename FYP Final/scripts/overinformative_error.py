import requests
from bs4 import BeautifulSoup
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.common.keys import Keys
from selenium.webdriver.support.wait import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.edge.options import Options
import configparser
import mysql.connector
import sys
import json
from os.path import dirname
sys.path.append(dirname(dirname(f'{__file__}')))
from v2.yaml_vuln import vuln_extract


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

edgeBrowser = create_webdriver()

if __name__ == "__main__":
    user_input = sys.argv[1]
    scan_id = int(sys.argv[2])

driver = edgeBrowser
url = user_input
driver.get(url)
loginid = ['abcd','u0000028']
password = ['abcd','1234']
error_messages = []

def testing(username, password, inputfields,driver):
    sampleElement = WebDriverWait(driver, 10).until(
    EC.presence_of_element_located((By.ID, inputfields[0])))

    sampleElement.send_keys(username)

    sampleElement2 = WebDriverWait(driver, 10).until(
        EC.presence_of_element_located((By.ID, inputfields[1])))
    
    sampleElement2.send_keys(password,Keys.RETURN)


conn = requests.get(url)
#get input fields
soup = BeautifulSoup(conn.content,features="lxml")
inputs = soup.find_all('input')
inputfield=[]
# Get the ids of the input fields
for tag in inputs:
    input = tag.get('id',None)
    if input is not None:
        inputfield.append(input)

for i in range(len(loginid)):
    testing(loginid[i],password[i],inputfield,driver)
    sampleElement2 = WebDriverWait(driver, 10).until(
    EC.presence_of_element_located((By.XPATH, '//*[@class="ui error message"]')))
    error_messages.append(str(sampleElement2))

if error_messages[0] == error_messages[1]:
    print('there is no vulnerabilitiy')
else:
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
    # Insert a row into the MySQL table
    cwe_id = "CWE-203"
    vuln_yml = vuln_extract(cwe_id)
    name = vuln_yml['name']
    # Insert a row into the MySQL table
    insert_query = "INSERT INTO vulnerabilities (scan_id, vulnerability_name, vulnerability_id, url, additional_information) VALUES (%s, %s, %s, %s, %s)"
    values = (scan_id, name, cwe_id, url,error_messages[0]) #Change this in the later part, don't hardcode
    db_cursor.execute(insert_query, values)
    db_connection.commit()

    print("This is a vulnerability. There is too much info")

from time import sleep

input_text_loginid = driver.find_element(By.ID,'loginId')
input_text_password = driver.find_element(By.ID,'password')
input_text_loginid.send_keys('u0000028')
input_text_password.send_keys('password',Keys.RETURN)

input_urls = []
test_input = 'Overinformative profile test'
urls_with_error = []
base_url = user_input
config = configparser.ConfigParser()
config.read("config.ini")
username = config.get('Advanced Scan Settings','scraping_username')
password = config.get('Advanced Scan Settings','scraping_password')
over_error = config.get('Advanced Scan Settings','scan_for_overinformative_error')

driver = create_webdriver()
if int(over_error) == 1:
    driver.get(base_url)
    def login():
        input_text_loginid = driver.find_element(By.ID,'loginId')
        input_text_password = driver.find_element(By.ID,'password')
        input_text_loginid.send_keys(username)
        input_text_password.send_keys(password,Keys.RETURN)

    login()
    page_source = driver.page_source
    #get input fields
    soup = BeautifulSoup(page_source,features="html.parser")
    for link in soup.find_all('a',class_="profile-fluid-btn"):
        # appending to a list
        input_urls.append(base_url+link.get('href'))  
    for link in soup.find_all('a',class_="ui right floated"):
        # appending to a list
        input_urls.append(base_url+link.get('href'))
    
    for url123 in input_urls:
        driver.get(url123)
        page_source = driver.page_source
        #using soup to change everything from hidden to not hidden
        soup = BeautifulSoup(page_source, features="html.parser")
        for item in soup.select("[type^='hidden']"):
            item.decompose()
        #using soup to find all the input field on the page
        inputs = soup.find_all('input')
        inputfield=[]
        for tag in inputs:
            input = tag.get('name',None)
            if input is not None:
                inputfield.append(input)
            
        #using soup again to look for dropdown boxes
        soup2 = BeautifulSoup(page_source, features="html.parser")
        inputs2 = soup2.find_all(class_="selection")
        dropdowns=[]
        for tag in inputs2:
            input2 = tag.get('class',None)
            if input2 is not None:
                dropdowns.append(input2)
        #If there is input fields but no dropdown boxes
        if inputfield !=[] and dropdowns == []:
            for i in range(2):
                driver.get(url123)
                for i in inputfield:
                    sampleElement = WebDriverWait(driver, 10).until(
                    EC.presence_of_element_located((By.NAME, i)))
                    #sampleElement.clear()
                    url1 = driver.current_url
                    if "relationship/search" in url1:
                        sampleElement.send_keys(f"system admin")          
                    else:
                        sampleElement.send_keys(f"{test_input}")
                sampleElement.send_keys(Keys.ENTER)
                if "relationship/search" in url1:
                    Selection=driver.find_elements(By.CLASS_NAME, "selection")
                    #To click to make the choices visable 
                    for field in Selection:
                        if field.is_displayed():
                            #click to open selection field
                            field.click()
                            sleep(0.2)
                            #find the first option
                            clcik=field.find_element(By.CLASS_NAME,"item")
                            #Select the first option
                            clcik.click()
                    add=driver.find_element(By.CSS_SELECTOR,".ui.right.floated.small.primary.button")
                    add.click()
                sleep(0.1)
                url = driver.current_url
                if url==base_url+"login":
                    login()
                    sleep(0.1)
            page_source = driver.page_source
            soup3 = BeautifulSoup(page_source,'html.parser')
            div_element = soup3.select_one('div.content > div.header')
            print('this is the element'+str(div_element))
            if div_element == 'Error':
                error_msg = soup3.select_one('div.content > p')
                print("This is the error"+str(error_msg))
                if "for key" in error_msg or "java.sql" in error_msg:
                    print(f'Oh no! This is a vulnerability in the ${url123}!')
                    urls_with_error.append(url123)
                else:
                    print('no vulnerability here')
        
        #If there is input fields and dropdown boxes
        if inputfield !=[] and dropdowns !=[]:
            for i in range(2):
                driver.get(url123)
                #To find selection fields to click to make the choices visable and interable 
                sleep(2)
                Selection=driver.find_elements(By.CLASS_NAME, "selection")
                
                #To click to make the choices visable 
                for field in Selection:
                    if field.is_displayed():
                        #click to open selection field
                        field.click()
                        sleep(0.2)
                        #find the first option
                        clcik=field.find_element(By.CLASS_NAME,"item")
                        #Select the first option
                        clcik.click()
                
                #Fill in all writeable inputfield with the payload
                payload1=test_input
                
                for i in inputfield:
                    url = driver.current_url
                    if "contact/phone/new" in url:
                        payload = "123456789"
                    elif "contact/email/new" in url:
                        payload = "test@gmail.com"
                    elif i =="partialNricOpt":
                        payload="123A"
                    elif i =="weddingDateOpt" or i=="dobOpt" or i == "expDate" or i == "issueDate":
                        payload="11/02/2023"
                    elif i == "phone":
                        payload = "12345678"
                    elif i == "email":
                        payload = "test@gmail.com"
                    elif i == "postalCode":
                        payload = "123456"
                    else:
                        payload=payload1
                    if i !='loginIdOpt' and i!="weddingDateOpt":
                        sampleElement = WebDriverWait(driver, 10).until(
                        EC.presence_of_element_located((By.NAME, i)))
                    sleep(0.1)
                    sampleElement.send_keys(f"{payload}")
                #Submit the form to test payload
                submit=driver.find_element(By.CSS_SELECTOR,".ui.right.floated.primary.button")
                #Select the first option
                submit.click()
            page_source = driver.page_source
            soup3 = BeautifulSoup(page_source,'html.parser')
            div_element = soup3.select_one('div.content > div.header')
            if div_element.text == 'Error':
                error_msg = soup3.select_one('div.content > p')
                if "for key" in error_msg.text or "java.sql" in error_msg.text:
                    print(f'Oh no! This is a vulnerability in the ${url123}!')
                    urls_with_error.append(url123)
                else:
                    print('no vulnerability here')

        #If there is no input fields but have dropdown boxes
        if inputfield ==[] and dropdowns !=[]:
            for i in range(2):
                driver.get(url123)
                #To find selection fields to click to make the choices visable and interable 
                sleep(2)
                Selection=driver.find_elements(By.CLASS_NAME, "selection")
                
                #To click to make the choices visable 
                for field in Selection:
                    if field.is_displayed():
                        #click to open selection field
                        field.click()
                        sleep(0.2)
                        #find the first option
                        clcik=field.find_element(By.CLASS_NAME,"item")
                        #Select the first option
                        clcik.click()
                #Submit the form to test payload
                submit=driver.find_element(By.CSS_SELECTOR,".ui.right.floated.primary.button")
                #Select the first option
                submit.click()
            page_source = driver.page_source
            soup3 = BeautifulSoup(page_source,'html.parser')
            div_element = soup3.select_one('div.content > div.header')
            if div_element.text == 'Error':
                error_msg = soup3.select_one('div.content > p')
                if "for key" in error_msg.text or "java.sql" in error_msg.text:
                    print(f'Oh no! This is a vulnerability in the ${url123}!')
                    urls_with_error.append(url123)
                else:
                    print('no vulnerability here')

    if urls_with_error is not None:

        db_cursor = db_connection.cursor()
        # Insert a row into the MySQL table
        cwe_id="CWE-209"
        vuln_yml = vuln_extract(cwe_id)
        name = vuln_yml['name']
        # Insert a row into the MySQL table
        insert_query = "INSERT INTO vulnerabilities (scan_id, vulnerability_name, vulnerability_id, url, additional_information) VALUES (%s, %s, %s, %s, %s)"
        values = []
        urls_with_error_dict = {
            "results":urls_with_error
        }
        # for url in urls_with_error:
        urls_with_error_dict_json = json.dumps(urls_with_error_dict)
        values.append([scan_id, name, cwe_id, url, urls_with_error_dict_json])
        db_cursor.executemany(insert_query, values)
        db_connection.commit()

        db_cursor.close()
        db_connection.close()
        print("This is a vulnerability. There is too much info")
        print(f"this is the list of urls with error: ${str(urls_with_error)}")
    else:
        print('there is no overinformative profile error')