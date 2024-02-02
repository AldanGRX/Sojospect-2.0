import requests
from bs4 import BeautifulSoup as soup
from urllib.parse import urljoin, urlsplit
import time
import json
'''
#----------------------USAGE---------------------------

import json

with open('crawl.txt','r') as crawl_file:
    for i in (crawl_file.readlines()):
        data_dict = json.loads(i) #Data is now a dictionary from json loads
        #Examples to read data
        #To print all fields
        for key in data_dict.keys():
            if(key.startswith("Param_")):
                print(data_dict[key])
                #Accessing input field name
                print(data_dict[key]['name'])
                #Accessing input field id
                print(data_dict[key]['id'])
                #Accessing default value
                print(data_dict[key]['value'])
                #Accessing input type
                print(data_dict[key]['type'])
        #To get method
        print(data_dict['Method']) #Could be None

        #To get endpoint
        print(data_dict['Endpoint']) #Could be None

        #To get parent url
        print(data_dict['URL'])

'''

#Modify the sleep timing at your own risk


csv_data = []
base_url = "http://testphp.vulnweb.com/"
domain = urlsplit(base_url).netloc
crawled_url = []
uncrawled_url = []
uncrawled_url.append(base_url)
open('./crawl.txt', 'w').close()

while True:
    #URL locating
    if urlsplit(uncrawled_url[0]).path != '/logout':#Preventing logout
        x = requests.get(uncrawled_url[0], headers={"x-auth-token":"eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJyaWNrIn0.lLdv2SY2TWzzXVKSahFDWPLcUHwpXpjsLnhwo0ioRFM"})
    else:
        get_dict = {
            "URL":uncrawled_url[0],
            "Endpoint":urlsplit(uncrawled_url[0]).path,
            "Method":"GET"
        }
        to_write_json = [json.dumps(get_dict)]
        with open("crawl.txt","a+") as file:
            file.writelines(row +'\n' for row in to_write_json)
        crawled_url.append(uncrawled_url.pop(0))
        if(len(uncrawled_url) == 0):
            break
        # time.sleep(1)
        continue
    page_soup = soup(x.content,"html.parser",from_encoding="iso-8859-1")
    for res in page_soup.find_all(lambda tag: tag.has_attr("href") or tag.has_attr("src")):
        if(res.has_attr('href')):
            link = res.get('href')
        elif(res.has_attr('src')):
            link = res.get('src')
        # link.replace("https://","")
        parsed_link = ""
        parsed_link = urljoin(base_url,link)
        # if(link.startswith("/")):
        #     parsed_link = urljoin(base_url,link)
        # else:
        #     if(urlsplit(link).scheme not in ["https","http"]):
        #         parsed_link = "https://"+link
        #     else:
        #         parsed_link = link
        if(urlsplit(parsed_link).netloc == domain):
            #Throw the links into uncrawled if they don't exist in crawled
            if parsed_link not in crawled_url and parsed_link not in uncrawled_url:
                uncrawled_url.append(parsed_link)
    to_write_json = []
    get_dict = {
        "URL":uncrawled_url[0],
        "Endpoint":urlsplit(uncrawled_url[0]).path,
        "Method":"GET"
    }
    to_write_json.append(json.dumps(get_dict))
    #Obtain the forms
    for form in page_soup.find_all('form'):
        endpoint = None
        url = uncrawled_url[0]
        method = None
        if(not form.has_attr('action') or len(form['action'].strip())==0):
            #Empty
            endpoint = None
        else:
            endpoint = form['action']
        method = form['method'].upper() if form.has_attr('method') else None
        inputs = form.find_all('input')
        consolidate_dict = {
            "URL":url,
            "Endpoint":endpoint,
            "Method":method,
        }
        param_count = 0
        for row in inputs:
            param_count+=1
            consolidate_dict[f"Param_{param_count}"] = {} #Initialize dict
            consolidate_dict[f"Param_{param_count}"]["class"] = row["class"] if row.has_attr("class") else None
            consolidate_dict[f"Param_{param_count}"]["id"] = row["id"] if row.has_attr("id") else None
            consolidate_dict[f"Param_{param_count}"]["name"] = row["name"] if row.has_attr("name") else None
            consolidate_dict[f"Param_{param_count}"]["type"] = row["type"] if row.has_attr("type") else None
            consolidate_dict[f"Param_{param_count}"]["value"] = row["value"] if row.has_attr("value") else None
        json_data = json.dumps(consolidate_dict)
        to_write_json.append(json_data)
    with open("./crawl.txt","a+") as file:
        file.writelines(row +'\n' for row in to_write_json)
    crawled_url.append(uncrawled_url.pop(0))
    if(len(uncrawled_url) == 0):
        break
    time.sleep(1)
    