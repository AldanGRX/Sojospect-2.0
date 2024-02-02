from scrapy.spiders import CrawlSpider, Rule
from scrapy.linkextractors import LinkExtractor
import json
from urllib.parse import urlsplit, urljoin
from scripts.seleniumBot import login_get_cookie_jar

class firstSpider(CrawlSpider):
    name="FirstSpider"
    allowed_domains = []
    start_urls = []
    javascript_links = set()
    custom_settings = {
        'LOG_LEVEL':'INFO',
        # 'CONCURRENT_REQUESTS':10,
        # 'DOWNLOAD_DELAY':5.0/10
    }
    rules = (
        Rule(LinkExtractor(),callback="parse_item",process_request='intercept_request',follow=True),
    )
    def login(self):
        # login_info = {"loginId": self.username, "password": self.password}
        # response = requests.post(
        #     "https://chmsdemo.greenfossil.com/authenticate", data=login_info
        # )
        session_cookie = login_get_cookie_jar('https://chmsdemo.greenfossil.com', self.username, self.password)
        self.cookies = session_cookie
    def __init__(self,username,password,url,scope,filename):
        super(firstSpider,self).__init__()
        self.allowed_domains = [scope]
        self.start_urls = [url]
        self.username = username
        self.password = password
        self.filename = filename
        self.login()
        print(self.cookies)
        open(filename,'w').close()

    def intercept_request(self,request,response):
        for cookie in self.cookies:
            request.cookies[cookie.name] = cookie.value
        if('logout' in response.url):
            self.login()
        else:
            return request
        
    def parse_item(self,response):
        if "text/html" in response.headers.get("content-type","").decode().lower():
            javascripts = response.xpath("//script")
            form = response.xpath("//form")
            # print(response.url)
            get_dict = {
                "URL":response.url,
                "Endpoint":urlsplit(response.url).path,
                "Method":"GET"
            }
            to_write_json = []
            to_write_json.append(json.dumps(get_dict))
            for record in javascripts:
                src = record.xpath("@src").get()
                href = record.xpath("@href").get()
                if src is not None:
                    url=urljoin(response.url,src)
                    domain = urlsplit(url).netloc
                    if domain not in self.allowed_domains or url in self.javascript_links:
                        continue
                    self.javascript_links.add(url)
                    to_write_json.append(json.dumps({
                        "URL":url,
                        "Endpoint":urlsplit(url).path,
                        "Method":"GET"
                    }))
                if href is not None:
                    url=urljoin(response.url,href)
                    domain = urlsplit(url).netloc
                    if domain not in self.allowed_domains or url in self.javascript_links:
                        continue
                    self.javascript_links.add(url)
                    to_write_json.append(json.dumps({
                        "URL":url,
                        "Endpoint":urlsplit(url).path,
                        "Method":"GET"
                    }))
            for record in form:
                # print(record)
                endpoint = record.xpath("@action").get()
                method = record.xpath("@method").get()
                inputs = record.xpath("input")
                consolidate_dict = {
                    "URL":response.url,
                    "Endpoint":endpoint,
                    "Method":method
                }
                
                
                param_count = 0
                for row in inputs:
                    param_count+=1
                    class_val = row.xpath("@class").get()
                    id = row.xpath("@id").get()
                    name = row.xpath("@name").get()
                    type_val = row.xpath("@type").get()
                    value = row.xpath("@value").get()
                    consolidate_dict[f"Param_{param_count}"] = {} #Initialize dict
                    consolidate_dict[f"Param_{param_count}"]["class"] = class_val
                    consolidate_dict[f"Param_{param_count}"]["id"] = id
                    consolidate_dict[f"Param_{param_count}"]["name"] = name
                    consolidate_dict[f"Param_{param_count}"]["type"] = type_val
                    consolidate_dict[f"Param_{param_count}"]["value"] = value
                json_data = json.dumps(consolidate_dict)
                to_write_json.append(json_data)
                # print(consolidate_dict)
            with open(self.filename,"a+") as file:
                file.writelines(row + '\n' for row in to_write_json)
            # print()

