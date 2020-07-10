#!/usr/bin/env python
# encoding: utf-8
"""
@author: Lone
@email: fanml@neusoft.com
@file: mongo_search.py
@time: 2020/6/16 14:01
"""
from pprint import pprint

import pymongo

# client = pymongo.MongoClient(host='localhost')
client = pymongo.MongoClient(host='10.240.200.1')
db = client.cves
collection = db.info

cursor = collection.find()
for i in cursor:
    print(i['_id'])
    apps = i['apps']
    print(len(apps))
    # print(f"app nums:{len(apps)}")
    # for app in apps:
    #     print(app)
    # pprint(i)
