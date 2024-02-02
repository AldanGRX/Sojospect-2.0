import seleniumBot
import configparser
import mysql.connector
import sys
from os.path import dirname
from urllib.parse import urlparse
sys.path.append(dirname(dirname(f'{__file__}')))
from v2.yaml_vuln import vuln_extract
import json

def checkCookie(username, password):
    cookie = seleniumBot.getCookie(url, username, password)
    # cookie = seleniumBot.getCookie_testing(url, username, password)
    print(cookie)
    if cookie['secure'] != True or cookie['httpOnly'] != True or (cookie['sameSite']).lower() == 'none':
        cwe_id = "CWE-1275-1004-614"
        vuln_yml = vuln_extract(cwe_id)
        name = vuln_yml['name']
        
        db_cursor = db_connection.cursor()
        # Insert a row into the MySQL table
        additional_information = {
            "secure":not cookie['secure'],
            "httpOnly":not cookie['httpOnly'],
            "sameSite": cookie['sameSite']
        }
        additional_information_json = json.dumps(additional_information)
        insert_query = "INSERT INTO vulnerabilities (scan_id, vulnerability_name, vulnerability_id, url,additional_information) VALUES (%s, %s, %s, %s, %s)"
        values = (scan_id, name, cwe_id, user_input,additional_information_json) #Change this in the later part, don't hardcode
        db_cursor.execute(insert_query, values)
        db_connection.commit()

        db_cursor.close()
        db_connection.close()
        
    else:
        result = "No vulnerabilities found"
        print(result)

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

db_host = config.get('SQL Database', 'db_host')
db_user = config.get('SQL Database', 'db_user')
db_password = config.get('SQL Database', 'db_password')

db_connection = mysql.connector.connect(
    host=db_host,
    user=db_user,
    password=db_password,
    database="vulnerabilities"
)

checkCookie(config['Advanced Scan Settings']['scraping_username'], config['Advanced Scan Settings']['scraping_password'])