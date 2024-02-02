from bs4 import BeautifulSoup
import re


def sql_error_check(response_text, error_xml_path):
    with open(error_xml_path) as file:
        data = file.read()
    
    Bs_data = BeautifulSoup(data,"xml")
    for dbms in Bs_data.find_all("dbms"):
        full_re = []
        for error in dbms.find_all("error"):
            full_re.append(error['regexp'])
        if(re.search(("(?i)"+"("+'|'.join(full_re)+")"),response_text)):
            error = {"DBMS" : dbms['value'], "Error" : full_re}
            return error
    return -1
        