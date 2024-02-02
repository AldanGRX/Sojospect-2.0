import requests
import json
from bs4 import BeautifulSoup
from urllib.parse import urlparse
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.common.by import By
from selenium.webdriver.support.wait import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium import webdriver
from selenium.webdriver.common.keys import Keys
import configparser
import mysql.connector
import sys
from os.path import dirname
sys.path.append(dirname(dirname(f'{__file__}')))
from v2.yaml_vuln import vuln_extract

# Detect available web browsers and create a webdriver
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

def trypass(password,idlist,username,edgeBrowser):

    sampleElement = WebDriverWait(edgeBrowser, 10).until(
    EC.presence_of_element_located((By.ID, idlist[0])))

    sampleElement.send_keys(username)

    sampleElement2 = WebDriverWait(edgeBrowser, 10).until(
        EC.presence_of_element_located((By.ID, idlist[1])))
    
    sampleElement2.send_keys(password)

    sampleElement.send_keys(Keys.ENTER)

def save_vuln_to_db(result) :
    db_connection = mysql.connector.connect(
        host=db_host,
        user=db_user,
        password=db_password,
        database="vulnerabilities"
    )
    db_cursor = db_connection.cursor()
    # Insert a row into the MySQL table
    cwe_id = "CWE-1391-307"
    vuln_yml = vuln_extract(cwe_id)
    name = vuln_yml['name']

    results = {
        "url" : url,
        "vulnerability" : result
    }
    results = json.dumps(results)

    insert_query = "INSERT INTO vulnerabilities (scan_id, vulnerability_name, vulnerability_id, url, additional_information) VALUES (%s, %s, %s, %s,%s)"
    values = (scan_id, name, cwe_id, initial_login_url, results) #Change this in the later part, don't hardcode
    db_cursor.execute(insert_query, values)
    db_connection.commit()

    db_cursor.close()
    db_connection.close()

if __name__ == "__main__":
    user_input = sys.argv[1]
    scan_id = int(sys.argv[2])

url = user_input
parsed_url = urlparse(user_input)
scheme = parsed_url.scheme
netloc = parsed_url.netloc
url = scheme + "://" + netloc

# Load the configuration file
config = configparser.ConfigParser()
config.read('config.ini')
# Get values from the config file
username = config.get('Advanced Scan Settings', 'scraping_username')
# password = config.get('Advanced Scan Settings', 'scraping_password')
# username = 'U0000028'
db_host = config.get('SQL Database', 'db_host')
db_user = config.get('SQL Database', 'db_user')
db_password = config.get('SQL Database', 'db_password')
passwordtotest = config.get('Advanced Scan Settings','bruteforce_amount')

edgeBrowser = create_webdriver()
conn = requests.get(url)
#password list
text_file = open("passwordlist.txt", "r")
newlist = text_file.read().split('\n')
text_file.close()
num=int(passwordtotest)
passlist=newlist[:num]
print(passlist)
#get input fields
soup = BeautifulSoup(conn.content,features="lxml")
inputs = soup.find_all('input')
inputfield=[]
# Get the ids of the input fields
for tag in inputs:
    input = tag.get('id',None)
    if input is not None:
        inputfield.append(input)
# This is the step for maximizing browser window
edgeBrowser.maximize_window()
# Browser will get navigated to the given URL
edgeBrowser.get(url)
initial_login_url = edgeBrowser.current_url

#For all password in list
count = 0
for i in passlist:
    count += 1
    trypass(i,inputfield,username,edgeBrowser) # UNCOMMENT BACK
    url=edgeBrowser.current_url # UNCOMMENT BACK

    # # TESTING ON DEMO.TESTFIRE.NET
    # initial_login_url = "https://demo.testfire.net/login.jsp"
    # credentials = {"uid" : username, "passw" : i}
    # response = requests.post("https://demo.testfire.net/doLogin", data=credentials)
    # url = response.url
    # print(url)
    # print(f'Attempting login {count} --> {username}:{i} --> {url}')

    #if still in login page
    if str(url) == initial_login_url :
        print('---------------------')
        #find error message
        try :
            page_source = edgeBrowser.page_source
            sampleElement2 = WebDriverWait(edgeBrowser, 10).until(
            EC.presence_of_element_located((By.XPATH, '//*[@class="ui error message"]')))
            a=sampleElement2.text
            error_msg = str(a)
            print(f"{error_msg}\n---------------------")
            if ("disabled" or "locked" or "suspended" or "timeout") in error_msg.lower() :
            # if "disabled" in error_msg.lower() or 'locked' in error_msg.lower() or 'suspended' in error_msg.lower() :
                print("Application is secure from bruteforce attacks.")
                break
        except :
            print("Returned error not found")
    else :
        save_vuln_to_db("allows usage of Weak Password/Common Password")
        break
    
    if count > 30 :
        save_vuln_to_db("has no proper rate limiting control")
        break
