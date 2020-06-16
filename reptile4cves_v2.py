#!/usr/bin/env python
# encoding: utf-8
"""
@author: Lone
@email: fanml@neusoft.com
@file: reptile4cves.py
@time: 2020/6/16 9:55
"""

import concurrent.futures
import re
import time
import operator
from functools import reduce, partial
from pprint import pprint

import requests
from fake_useragent import UserAgent
from bs4 import BeautifulSoup
import pymongo

url = 'https://nvd.nist.gov/vuln/search/results'

headers = {
    'User-Agent': UserAgent().chrome
}


def get_matching_records(vendor, product, version):
    try:
        params = {
            "form_type": "Advanced",
            "cves": "on",
            "cpe_version": f"cpe:/a:{vendor}:{product}:{version}",
            "startIndex": 0
        }
        r = requests.get(url, params=params, headers=headers)
        r.raise_for_status()
        r.encoding = r.apparent_encoding
        soup = BeautifulSoup(r.text, "html.parser")
        matching_records = soup.find('strong', attrs={'data-testid': 'vuln-matching-records-count'}).get_text()
        matching_records = int(matching_records)
        print(f"matching_records: {matching_records}")
        return matching_records
    except Exception as err:
        print(err)
        print('Failed')


def get_one_page(index, vendor, product, version):
    try:
        cve_info = []
        params = {
            "form_type": "Advanced",
            "cves": "on",
            "cpe_version": f"cpe:/a:{vendor}:{product}:{version}",
            "startIndex": index
        }
        r = requests.get(url, params=params, headers=headers)
        r.raise_for_status()
        r.encoding = r.apparent_encoding
        # print(r.apparent_encoding)
        # print(r.url)
        # print(r.status_code)
        # print(r.text)
        soup = BeautifulSoup(r.text, "html.parser")
        trs = soup.find_all('tr', attrs={'data-testid': re.compile(r'vuln-row-(\d+)?')})
        """
        text
        \n\nCVE-2020-6498\n\n\nIncorrect implementation in user interface in Google Chrome on iOS prior to 83.0.4103.88
         allowed a remote attacker to perform domain spoofing via a crafted HTML page.
         \nPublished:\nJune 03, 2020; 07:15:12 PM -04:00\n\n\n\nV3.1: 6.5 MEDIUM\n\n\n\xa0\xa0\xa0\xa0V2: 4.3 MEDIUM\n\n\n'
        """
        # print(f'trs len: {len(trs)}')
        # lines = len(trs)
        for tr in trs:
            tr = tr.get_text()
            tr = tr.replace('\n', '').replace('\xa0', '')
            # print(tr)
            find = (
                re.search(r'(?P<cve>CVE-\d{4}-\d{4,5})(?P<summary>.*?)(?P<published>Published:.*?)(?P<level>V.*)', tr)
            )
            find_dict = find.groupdict()
            # print(find)
            # print(len(find))
            if 'HIGH' in find_dict['level'] or 'CRITICAL' in find_dict['level']:
                # V3.1: 6.5 MEDIUMV2: 4.3 MEDIUM
                score = level = None
                str_list = find_dict['level'].split('V')
                # ['', '3.1: 6.5 LOW', '2: 4.3 CRITICAL']
                try:
                    if 'HIGH' in str_list[1] or 'CRITICAL' in str_list[1]:
                        level_score = str_list[1].split()
                        score = level_score[1]
                        level = level_score[2]
                    else:
                        level_score = str_list[2].split()
                        score = level_score[1]
                        level = level_score[2]
                except IndexError:
                    pass
                tmp = {
                    'cve': find_dict.get('cve'),
                    'summary': find_dict.get('summary'),
                    'published': find_dict.get('published'),
                    'level': level,
                    'score': score,
                    'detail': f'https://nvd.nist.gov/vuln/detail/{find_dict.get("cve")}',
                }
                cve_info.append(tmp)
        # print(f"cve_info: {cve_info}")
        return cve_info
    except Exception as err:
        print(err)
        print('Failed')


def get_all_page(start_indexes, product):
    res = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
        # res.extend(executor.map(get_one_page, start_indexes))
        res.extend(executor.map(partial(get_one_page, **product), start_indexes))
    res = reduce(operator.add, res)
    # print(f"res: {res}")
    return res


def get_one_product(product):
    matching_records = get_matching_records(**product)
    pages = matching_records // 20 + 1
    start_indexes = []
    for i in range(pages):
        start_indexes.append(i * 20)
    res = {"vendor": product.get('vendor'), "product": product.get('product'), "version": product.get('version'),
           'cves': get_all_page(start_indexes, product)}
    # print('Get one product res: ')
    # pprint(res)
    print('*' * 40)
    print(f'Get one product res len: {len(res["cves"])}')
    print('*' * 40)

    return res


def get_all_product(products):
    res = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
        res.extend(executor.map(get_one_product, products))
    # res = reduce(operator.add, res)
    # print("Get all products res")
    # pprint(res)
    return res


def write_data_to_mongo(data):
    client = pymongo.MongoClient(host='localhost')
    db = client.cves
    collection = db.info
    condition = {'pcid': data.get('pcid')}
    if not collection.find_one(condition):
        print('running in create')
        result = collection.insert_one(data)
    else:
        print('running in update')
        result = collection.update(condition, data)
    print(result)
    result = collection.find_one(condition)
    print(type(result))
    print(result)


if __name__ == '__main__':
    # 将kafka数据解析为以下格式
    apps_info = {
        'pcid': '5678',
        'products':  [
            {
                'vendor': 'google',
                'product': 'chrome',
                'version': '80.0.3987.87'
            },
            # {
            #     'vendor': 'apache',
            #     'product': 'tomcat',
            #     'version': '7.0.92'
            # },
            {
                'vendor': 'apache',
                'product': 'http_server',
                'version': '2.4.38'
            },
            {
                'vendor': 'oracle',
                'product': 'mysql',
                'version': '5.7.21'
            },
            {
                'vendor': 'mongoosejs',
                'product': 'mongoose',
                'version': '4.2.8'
            },
            {
                'vendor': 'git',
                'product': 'git',
                'version': '2.22.0'
            },
        ]
    }

    start_time = time.perf_counter()
    # 爬取数据
    res = {'pcid': apps_info.get('pcid'), 'apps': get_all_product(apps_info.get("products"))}
    # 更新数据到mongo
    write_data_to_mongo(res)
    end_time = time.perf_counter()
    print('Finish in {} seconds'.format(end_time - start_time))
