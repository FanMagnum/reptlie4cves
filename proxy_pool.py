#!/usr/bin/env python
# encoding: utf-8
"""
@author: Lone
@email: fanml@neusoft.com
@file: proxy_pool.py
@time: 2020/6/17 9:28
"""
import random
import time

import pymongo
import requests
from bs4 import BeautifulSoup
from fake_useragent import UserAgent

url = 'https://www.kuaidaili.com/free'

headers = {
    'User-Agent': UserAgent().chrome
}


def get_proxy_ip():
    try:
        proxy_ip = []
        for i in range(1, 20):
            time.sleep(1)
            page_url = url + f'/inha/{i}/'
            print(page_url)
            r = requests.get(page_url, headers=headers)
            r.raise_for_status()
            r.encoding = r.apparent_encoding
            soup = BeautifulSoup(r.text, "html.parser")
            r.close()
            td_ip = soup.find_all('td', attrs={'data-title': 'IP'})
            td_port = soup.find_all('td', attrs={'data-title': 'PORT'})
            # print(td_ip, td_port)
            for ip, port in zip(td_ip, td_port):
                # {"https": "223.241.1.81:4216"}
                # print('running in for')
                proxy_ip.append({'http': f'{ip.get_text()}:{port.get_text()}'})
        return proxy_ip
    except Exception as err:
        print(err)
        print('Failed')
        return []


if __name__ == '__main__':
    start_time = time.perf_counter()
    proxy_ip = get_proxy_ip()
    data = {'proxy_ip_pool': proxy_ip}
    print(proxy_ip)
    print(len(proxy_ip))
    for i in range(5):
        print(random.choice(proxy_ip))
    end_time = time.perf_counter()
    print('Finish in {} seconds'.format(end_time - start_time))
