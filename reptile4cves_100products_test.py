#!/usr/bin/env python
# encoding: utf-8
"""
@author: Lone
@email: fanml@neusoft.com
@file: reptile4cves.py
@time: 2020/6/16 9:55
"""

import concurrent.futures
import random
import re
import time
import operator
from functools import reduce, partial
from pprint import pprint

import requests
from fake_useragent import UserAgent
from bs4 import BeautifulSoup
import pymongo
from proxy_pool import get_proxy_ip

url = 'https://nvd.nist.gov/vuln/search/results'

headers = {
    'User-Agent': UserAgent().random
}

def get_matching_records(vendor, product, version):
    try:
        params = {
            "form_type": "Advanced",
            "cves": "on",
            "cpe_version": f"cpe:/a:{vendor}:{product}:{version}",
            "startIndex": 0
        }
        # r = requests.get(url, params=params, headers=headers, proxies=random.choice(proxy_ip_pool))
        r = requests.get(url, params=params, headers=headers)
        r.raise_for_status()
        r.encoding = r.apparent_encoding
        soup = BeautifulSoup(r.text, "html.parser")
        r.close()
        matching_records = soup.find('strong', attrs={'data-testid': 'vuln-matching-records-count'}).get_text()
        matching_records = int(matching_records)
        print(f"matching_records: {matching_records}")
        return matching_records
    except Exception as err:
        print('running in get_matching_records err')
        print(err)
        print('Failed')
        return None


def get_one_page(index, vendor, product, version):
    try:
        cve_info = []
        params = {
            "form_type": "Advanced",
            "cves": "on",
            "cpe_version": f"cpe:/a:{vendor}:{product}:{version}",
            "startIndex": index
        }
        # 设置重连次数
        # r = requests.get(url, params=params, headers=headers, proxies=random.choice(proxy_ip_pool))
        r = requests.get(url, params=params, headers=headers)
        r.raise_for_status()
        r.encoding = r.apparent_encoding
        soup = BeautifulSoup(r.text, "html.parser")
        r.close()
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
        print('running in get_one_page err')
        print(err)
        print('Failed')
        return []


def get_all_page(start_indexes, product):
    res = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
        # res.extend(executor.map(get_one_page, start_indexes))
        res.extend(executor.map(partial(get_one_page, **product), start_indexes))
    res = reduce(operator.add, res)
    # print(f"res: {res}")
    return res


def get_one_product(product):
    try:
        matching_records = get_matching_records(**product)
        if matching_records:
            pages = matching_records // 20 + 1
            start_indexes = []
            for i in range(pages):
                start_indexes.append(i * 20)
            res = {"vendor": product.get('vendor'), "product": product.get('product'),
                   "version": product.get('version'),
                   'cves': get_all_page(start_indexes, product)}
            # print('Get one product res: ')
            # pprint(res)
            print('*' * 40)
            print(f'Get one product res len: {len(res["cves"])}')
            print('*' * 40)
            return res
        else:
            # NATIONAL VULNERABILITY DATABASE没有收录此版本信息 cve为None
            return {"vendor": product.get('vendor'), "product": product.get('product'),
                    "version": product.get('version'),
                    'cves': None}
    except Exception as err:
        print('running in get_one_product err')
        print(err)
        print('Failed')
        return {"vendor": product.get('vendor'), "product": product.get('product'),
                "version": product.get('version'),
                'cves': None}


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
        'pcid': '1234',
        'products': [
            {
                'vendor': 'jetbrains',
                'product': 'pycharm',
                'version': f'2.7.{i}'
            } for i in range(1, 5)
        ]
    }

    apps_info['products'] += [
        {
            'vendor': 'jetbrains',
            'product': 'pycharm',
            'version': f'3.1.{i}'
        } for i in range(1, 5)
    ]

    apps_info['products'] += [
        {
            'vendor': 'cloudfoundry',
            'product': 'cf-mysql-release',
            'version': f'{i}'
        } for i in range(1, 24)
    ]
    #
    apps_info['products'] += [
        {
            'vendor': 'apache',
            'product': 'mod_python',
            'version': f'2.{i}'
        } for i in range(0, 8)
    ]
    apps_info['products'] += [
        {
            'vendor': 'appium',
            'product': 'appium-chromedriver',
            'version': f'2.0.{i}'
        } for i in range(0, 11)
    ]
    apps_info['products'] += [
        {
            'vendor': 'google',
            'product': 'chrome',
            'version': f'76.0.3809.{i}'
        } for i in range(0, 1)
    ]
    print('products nums ', len(apps_info['products']))
    start_time = time.perf_counter()
    # 爬取数据
    res = {'pcid': apps_info.get('pcid'), 'apps': get_all_product(apps_info.get("products"))}

    # res = {'pcid': apps_info.get('pcid')}
    # res['apps'] = []
    # length = len(apps_info['products'])
    # start = 0
    # end = 20
    # while length > 0:
    #     res['apps'].append(get_all_product(apps_info.get('products')[start:end]))
    #     start = end
    #     end += 20
    #     length -= 20
    #     print(f"length: {length}")
    print(res)
    # 更新数据到mongo
    write_data_to_mongo(res)
    end_time = time.perf_counter()
    print('Finish in {} seconds'.format(end_time - start_time))
