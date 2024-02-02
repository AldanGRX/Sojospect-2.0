import requests
from jinja2 import Template
from os.path import dirname
from selenium.webdriver.chrome.options import Options
from selenium import webdriver
from selenium.webdriver.edge.options import Options
import os
import sys
import configparser
import mysql.connector
from os.path import dirname
sys.path.append(dirname(dirname(f'{__file__}')))
from v2.yaml_vuln import vuln_extract

if __name__ == "__main__":
    user_input = sys.argv[1] # this is the domain
    scan_id = int(sys.argv[2])


base_url = user_input
config = configparser.ConfigParser()
config.read("config.ini")
clickjacking_vulnerable = True


resp = requests.get(base_url)
for k,v in resp.headers.items():
    if((k.lower() == "x-frame-options" and (v.lower() == "sameorigin" or v.lower() == "deny")) or
        (k.lower() == "content-security-policy" and ("frame-ancestors 'none'" in v.lower() or "frame-ancestors 'self'" in v.lower()))):
        clickjacking_vulnerable = False
    

if clickjacking_vulnerable:
    print("Website is potentially vulnerable to clickjacking...")
    print("Performing iframe check to make sure...")
    #attempt to load POC
    with open(f"{dirname(__file__)}/clickjacking-poc.html") as file:
        tm = Template(file.read())
        msg = tm.render(source=base_url)
        with open(f"{dirname(__file__)}/temp.html","w") as temp_file:
            temp_file.write(msg)
    browser = None
    try:
        # Try creating a Chrome webdriver
        chrome_options = Options()
        chrome_options.add_argument("headless")
        browser = webdriver.Chrome(options=chrome_options)
    except:
        try:
            # Try creating a Firefox webdriver
            firefox_options = webdriver.FirefoxOptions()
            firefox_options.add_argument("headless") 
            browser = webdriver.Firefox(options=firefox_options)
        except:
            try:
                from selenium.webdriver.edge.options import Options as EdgeOptions
                # Try creating an Edge webdriver
                options = EdgeOptions()
                options.use_chromium = True
                options.add_argument("headless")
                browser = webdriver.Edge(options=options)
            except:
                raise Exception("No suitable browser found")
    if browser != None:
        browser.get(f'file://{dirname(__file__)}/temp.html')
        # browser.switch_to.frame(browser.find_element(By.TAG_NAME, "iframe"))
        logs = browser.get_log("browser")
        for line in logs:
            if("message" in line.keys() and ("refused to display" in line["message"].lower() or "refused to frame" in line["message"].lower())):
                clickjacking_vulnerable = False
        browser.close()
    else:
        print("skipping active check...")
    os.remove(f'{dirname(__file__)}/temp.html')
    print("Temp file removed")
    print("Vulnerable to clickjacking")
else:
    print("Website is not vulnerable to clickjacking")

if clickjacking_vulnerable:
    #SQL query
    print("Clickjacking detected")
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
    cwe_id = "CAPEC-103"
    # Insert a row into the MySQL table
    vuln_yml = vuln_extract(cwe_id)
    name = vuln_yml["name"]

    insert_query = "INSERT INTO vulnerabilities (scan_id, vulnerability_name, vulnerability_id, url) VALUES (%s, %s, %s, %s)"
    values = []
    values.append([scan_id,name,cwe_id,user_input])
    db_cursor.executemany(insert_query, values)# Insert multiple rows together
    db_connection.commit()

    db_cursor.close()
    db_connection.close()