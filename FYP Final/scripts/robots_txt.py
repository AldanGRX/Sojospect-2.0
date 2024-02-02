import sys
import configparser
import mysql.connector
from os.path import dirname
sys.path.append(dirname(dirname(f'{__file__}')))
from v2.yaml_vuln import vuln_extract
import requests
if __name__ == "__main__":
    user_input = sys.argv[1]
    scan_id = int(sys.argv[2])

url = user_input + '/robots.txt'

input_urls = []
test = 0
robots_exists = True
resp = requests.get(url)
if(resp.status_code == 404):
    robots_exists = False

if not robots_exists:
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

    db_cursor = db_connection.cursor()

    cwe_id = "CUST-robots"
    vuln_yml = vuln_extract(cwe_id)
    name = vuln_yml['name']
    # Insert a row into the MySQL table
    insert_query = "INSERT INTO vulnerabilities (scan_id, vulnerability_name, vulnerability_id, url, additional_information) VALUES (%s, %s, %s, %s,%s)"
    values = (scan_id, name, cwe_id, user_input, None) 

    db_cursor.execute(insert_query, values)
    db_connection.commit()

    db_cursor.close()
    db_connection.close()


