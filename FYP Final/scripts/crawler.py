from scrapy.crawler import CrawlerProcess
import configparser
import sys
from os.path import dirname
from urllib.parse import urlsplit
sys.path.append(dirname(dirname(f'{__file__}')))
from webcrawler.webcrawler.spiders.webcrawler import firstSpider
if __name__ == "__main__":
    user_input = sys.argv[1]
    config = configparser.ConfigParser()
    config.read("config.ini")
    username = config.get('Advanced Scan Settings','scraping_username')
    password = config.get('Advanced Scan Settings','scraping_password')
    filename = config.get('Advanced Scan Settings', 'mapped_file')
    url = user_input
    domain = urlsplit(url).netloc
    process = CrawlerProcess()
    process.crawl(firstSpider, username=username, password=password, url=url,scope=domain,filename=filename)
    process.start()