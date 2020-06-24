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
# from proxy_pool import get_proxy_ip

url = 'https://nvd.nist.gov/vuln/search/results'

headers = {
    'User-Agent': UserAgent().random
}

requests.adapters.DEFAULT_RETRIES = 5
s = requests.session()
s.keep_alive = False


# proxy_ip_pool = get_proxy_ip()


def get_matching_records(vendor, product, version, _):
    try:
        params = {
            "form_type": "Advanced",
            "cves": "on",
            "cpe_version": f"cpe:/a:{vendor}:{product}:{version}",
            "startIndex": 0
        }
        r = s.get(url, params=params, headers=headers)
        r.raise_for_status()
        r.encoding = r.apparent_encoding
        soup = BeautifulSoup(r.text, "html.parser")
        r.close()
        matching_records = soup.find('strong', attrs={'data-testid': 'vuln-matching-records-count'}).get_text()
        matching_records = int(matching_records)
        return matching_records
    except Exception as err:
        print('running in get_matching_records err')
        print(err)
        print('Failed')
        return None


def get_one_page(index, vendor, product, version, _):
    try:
        cve_info = []
        params = {
            "form_type": "Advanced",
            "cves": "on",
            "cpe_version": f"cpe:/a:{vendor}:{product}:{version}",
            "startIndex": index
        }
        r = s.get(url, params=params, headers=headers)
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
        for tr in trs:
            tr = tr.get_text()
            tr = tr.replace('\n', '').replace('\xa0', '')
            # print(tr)
            find = (
                re.search(r'(?P<cve>CVE-\d{4}-\d{4,5})(?P<summary>.*?)(?P<published>Published:.*?)(?P<level>V.*)', tr)
            )
            find_dict = find.groupdict()
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
        return cve_info
    except Exception as err:
        print('running in get_one_page err')
        print(err)
        print('Failed')
        return []


def get_all_page(start_indexes, app):
    res = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
        res.extend(executor.map(partial(get_one_page, **app), start_indexes))
    res = reduce(operator.add, res)
    return res


def get_one_app(app):
    print(f"app: {app}")
    try:
        # 先去apps库里查找是否有记录
        client = pymongo.MongoClient(host='localhost')
        db = client.cves
        collection = db.apps
        condition = {'vendor': app.get('vendor'), 'product': app.get('product'), 'version': app.get('version')}
        res = collection.find_one(condition)
        if not res:
            # 没有记录，启动爬虫
            print("==============================>Running in spider")
            matching_records = get_matching_records(**app)
            print(f'matching_records: {matching_records}')
            if matching_records:
                pages = matching_records // 20 + 1
                start_indexes = []
                for i in range(pages):
                    start_indexes.append(i * 20)
                res = {"vendor": app.get('vendor'), "product": app.get('product'),
                       "version": app.get('version'),
                       'cves': get_all_page(start_indexes, app)}
                print('*' * 40)
                print(f'Get one product res len: {len(res["cves"])}')
                print('*' * 40)
                # 爬取后数据加入apps库
                collection.insert_one(res)
                res['installed_date'] = app.get('installed_date')
                return res
            else:
                # NATIONAL VULNERABILITY DATABASE没有收录此版本信息 cve为None
                res = {"vendor": app.get('vendor'), "product": app.get('product'),
                       "version": app.get('version'), 'cves': None}
                collection.insert_one(res)
                res['installed_date'] = app.get('installed_date')
                return res
        else:
            # apps库中有记录直接返回
            res.pop('_id')
            res['installed_date'] = app.get('installed_date')
            return res
    except Exception as err:
        # 爬取过程中报错 返回None
        print('running in get_one_app err')
        print(err)
        print('Failed')
        return {"vendor": app.get('vendor'), "product": app.get('product'),
                "version": app.get('version'),
                'cves': None}


def get_all_app(apps):
    res = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
        res.extend(executor.map(get_one_app, apps))
    return res


def write_data_to_mongo(data):
    client = pymongo.MongoClient(host='localhost')
    db = client.cves
    collection = db.info
    condition = {'_id': data.get('_id')}
    if not collection.find_one(condition):
        print('running in create')
        result = collection.insert_one(data)
    else:
        print('running in update')
        result = collection.update(condition, data)
    print(result)
    result = collection.find_one(condition)
    # print(type(result))
    print(result)


if __name__ == '__main__':
    # 将kafka数据解析为以下格式
    apps_info = {
        'pcid': '4567',
        'apps': [
            {
                'vendor': 'google',
                'product': 'chrome',
                'version': '80.0.3987.87',
                'installed_date': '2017-05-12'
            },
    #         {
    #             'vendor': 'apache',
    #             'product': 'tomcat',
    #             'version': '7.0.92'
    #         },
    #         {
    #             'vendor': 'apache',
    #             'product': 'http_server',
    #             'version': '2.4.38'
    #         },
    #         {
    #             'vendor': 'oracle',
    #             'product': 'mysql',
    #             'version': '5.7.14'
    #         },
    #         {
    #             'vendor': 'mongoosejs',
    #             'product': 'mongoose',
    #             'version': '4.2.8'
    #         },
    #         {
    #             'vendor': 'git',
    #             'product': 'git',
    #             'version': '2.22.0'
    #         },
    #         {
    #             'vendor': 'tencent',
    #             'product': 'foxmail ',
    #             'version': '7.2.11.303'
    #         },
    #         {
    #             'vendor': 'postgresql',
    #             'product': 'postgresql',
    #             'version': '10.0'
    #         },
    #         {
    #             'vendor': 'getpostman',
    #             'product': 'postman',
    #             'version': '4.3.2'
    #         },
    #         {
    #             'vendor': 'jetbrains',
    #             'product': 'pycharm',
    #             'version': '3.4.1'
    #         },
    #         {
    #             'vendor': 'mozilla',
    #             'product': 'firefox',
    #             'version': '70.0.1'
    #         },
    #         {
    #             'vendor': 'apple',
    #             'product': 'apple_remote_desktop',
    #             'version': '2.1.0'
    #         },
    #         {
    #             'vendor': 'navicat',
    #             'product': 'navicat',
    #             'version': '10.0'
    #         },
    #         {
    #             'vendor': 'wireshark',
    #             'product': 'wireshark',
    #             'version': '3.0.0'
    #         },
    #         {
    #             'vendor': 'anynines',
    #             'product': 'elasticsearch',
    #             'version': '2.1.0'
    #         },
    #         {
    #             'vendor': 'anynines',
    #             'product': 'logme',
    #             'version': '2.1.2'
    #         },
    #         {
    #             'vendor': 'anynines',
    #             'product': 'mongodb',
    #             'version': '2.1.2'
    #         },
    #         {
    #             'vendor': 'teamviewer',
    #             'product': 'teamviewer',
    #             'version': '11.0.224042'
    #         },
    #         {
    #             'vendor': 'mobatek',
    #             'product': 'mobaxterm',
    #             'version': '11.1'
    #         },
    #         {
    #             'vendor': 'wazuh',
    #             'product': 'wazuh',
    #             'version': '2.1.1'
    #         },
    #         {
    #             'vendor': '74cms',
    #             'product': '74cms',
    #             'version': '5.0.1'
    #         },
    #         {
    #             'vendor': 'acronis',
    #             'product': 'components_for_remote_installation',
    #             'version': '11.0.17318'
    #         },
    #         {
    #             'vendor': 'afterlogic',
    #             'product': 'aurora',
    #             'version': '8.3.11'
    #         },
    #         {
    #             'vendor': 'beyondtrust',
    #             'product': 'remote_support',
    #             'version': '9.2.3'
    #         },
    #         {
    #             'vendor': 'apache',
    #             'product': 'openoffice',
    #             'version': '2.4.3'
    #         },
    #         {
    #             'vendor': 'adobe',
    #             'product': 'flash_player',
    #             'version': '28.0.0.126'
    #         },
    #         {
    #             'vendor': 'add-in-express',
    #             'product': 'duplicate_remover_for_microsoft_excel',
    #             'version': '2.5.0'
    #         },
    #         {
    #             'vendor': 'microsoft',
    #             'product': 'visual_studio_code',
    #             'version': '2019.5.18875'
    #         },
    #         {
    #             'vendor': 'microsoft',
    #             'product': 'excel',
    #             'version': '2013'
    #         },
    #         {
    #             'vendor': 'microsoft',
    #             'product': 'ie',
    #             'version': '5.00.2919.6307'
    #         },
    #         {
    #             'vendor': 'microsoft',
    #             'product': 'office',
    #             'version': '2003'
    #         },
    #         {
    #             'vendor': 'microsoft',
    #             'product': 'office',
    #             'version': '2019'
    #         },
    #         {
    #             'vendor': 'microsoft',
    #             'product': 'powerpoint',
    #             'version': '2013'
    #         },
    #         {
    #             'vendor': 'microsoft',
    #             'product': 'powerpoint',
    #             'version': '2016'
    #         },
    #         {
    #             'vendor': 'microsoft',
    #             'product': 'visio',
    #             'version': '2016'
    #         },
    #         {
    #             'vendor': 'microsoft',
    #             'product': 'word',
    #             'version': '16.0.11929.20198'
    #         },
    #         {
    #             'vendor': 'microsoft',
    #             'product': 'yammer',
    #             'version': '5.6.9'
    #         },
    #         {
    #             'vendor': 'xmind',
    #             'product': 'xmind',
    #             'version': '3.4.1'
    #         },
    #         {
    #             'vendor': 'sublimetext',
    #             'product': 'sublime_text_3',
    #             'version': '3.1.1'
    #         },
        ]
    }
    # apps_info['apps'] += [
    #     {
    #         'vendor': 'jetbrains',
    #         'product': 'pycharm',
    #         'version': f'3.1.{i}'
    #     } for i in range(1, 5)
    # ]

    # apps_info['apps'] += [
    #     {
    #         'vendor': 'cloudfoundry',
    #         'product': 'cf-mysql-release',
    #         'version': f'{i}'
    #     } for i in range(1, 24)
    # ]
    # #
    # apps_info['apps'] += [
    #     {
    #         'vendor': 'apache',
    #         'product': 'mod_python',
    #         'version': f'2.{i}'
    #     } for i in range(0, 8)
    # ]
    # apps_info['apps'] += [
    #     {
    #         'vendor': 'appium',
    #         'product': 'appium-chromedriver',
    #         'version': f'2.0.{i}'
    #     } for i in range(0, 11)
    # ]
    # apps_info['apps'] += [
    #     {
    #         'vendor': 'google',
    #         'product': 'chrome',
    #         'version': f'76.0.3809.{i}'
    #     } for i in range(1, 16)
    # ]

    start_time = time.perf_counter()
    # 爬取数据
    print('apps nums ', len(apps_info['apps']))
    # res = {'pcid': apps_info.get('pcid'), 'apps': get_all_app(apps_info.get("apps"))}
    res = {'_id': apps_info.get('pcid'), 'apps': []}
    length = len(apps_info['apps'])
    start = 0
    end = 20
    while length > 0:
        tmp = apps_info.get('apps')[start:end]
        res['apps'].extend(get_all_app(tmp))
        start = end
        end += 20
        length -= 20
        print(f"length: {length}")
    print(len(res['apps']))
    # 更新数据到mongo
    write_data_to_mongo(res)
    end_time = time.perf_counter()
    print('Finish in {} seconds'.format(end_time - start_time))
