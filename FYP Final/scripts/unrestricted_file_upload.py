import os
import time
import configparser
from seleniumBot import driver
from seleniumBot import userLogin
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
import mysql.connector
import sys
import json
from os.path import dirname
import base64
sys.path.append(dirname(dirname(f'{__file__}')))
from v2.yaml_vuln import vuln_extract



if __name__ == "__main__":
    user_input = sys.argv[1]
    scan_id = int(sys.argv[2])

# Load the configuration file
config = configparser.ConfigParser()
config.read('config.ini')

db_host = config.get('SQL Database', 'db_host')
db_user = config.get('SQL Database', 'db_user')
db_password = config.get('SQL Database', 'db_password')
username = config['Advanced Scan Settings']['scraping_username']
password = config['Advanced Scan Settings']['scraping_password']

db_connection = mysql.connector.connect(
    host=db_host,
    user=db_user,
    password=db_password,
    database="vulnerabilities"
)

target_url = user_input
fileList = []
for filename in os.listdir('testFiles'):
    fileList.append(os.path.join('testFiles', filename))

homePage = userLogin(target_url, username, password)
# role = driver.find_element(By.CSS_SELECTOR, 'span.label').text
role = "Member"

unrestricted_count = 0

for i in range(len(fileList)):
    
    if role == 'Administrator':
        WebDriverWait(driver, 10).until(EC.presence_of_element_located((By.CSS_SELECTOR, 'div.dropdown')))
        homePage = driver.find_element(By.CSS_SELECTOR, 'div.dropdown div a').get_attribute('href')
        driver.get(homePage+'/editPhoto')


    elif role != 'Administrator':
        driver.get(homePage+'/editPhoto')


    fileUpload = WebDriverWait(driver, 10).until(EC.presence_of_element_located((By.ID, 'photoSelectBtn')))

    print(fileList[i])

    with open(fileList[i], "rb") as image_file:
        encoded_string = base64.b64encode(image_file.read())
        source = "data:image/jpeg;base64,"+encoded_string.decode()
    js =f'initCroppie("/user/profile/925/editPhoto", "{source}", "croppie-form", "scaled-photo", `{{"enableZoom":true,"showZoomer":true,"viewport":{{"width":200,"height":200,"type":"square"}},"boundary":{{"width":200,"height":200}}}}`, `3`, `{{"type":"blob","format":"jpeg","circle":false,"quality":0.9,"size":"original"}}`)'
    driver.execute_script(js)
    driver.find_element(By.CSS_SELECTOR, "#croppie-form>button[type='submit']").click()
    logs = driver.get_log("browser")
    restricted = False
    time.sleep(3)
    for line in logs:
        if("message" in line.keys() and not 'Failed to fetch'.lower() in line['message'].lower()):
            print("Failed to submit")
            restricted=True
    if not restricted:
        unrestricted_count+=1

if unrestricted_count > 0:
    db_cursor = db_connection.cursor()
    # Insert a row into the MySQL table
    cwe_id = "CWE-434"
    vuln_yml = vuln_extract(cwe_id)
    name = vuln_yml["name"]
    #Try not to hardcode CHANGE this url
    url = homePage + '/editPhoto'
    url_dict = {
        'url':url
    }
    url_dict_json = json.dumps(url_dict)
    insert_query = "INSERT INTO vulnerabilities (scan_id, vulnerability_name, vulnerability_id, url, additional_information) VALUES (%s, %s, %s, %s, %s)"
    values = (scan_id,name,cwe_id,user_input,url_dict_json)
    db_cursor.execute(insert_query, values)
    db_connection.commit()

    db_cursor.close()
    db_connection.close()

    message = 'Unrestricted file upload vulnerability detected'
else:
    message = 'Unrestricted file upload vulnerability not detected'

print('finished testing')
driver.quit()