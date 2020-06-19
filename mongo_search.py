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

client = pymongo.MongoClient(host='localhost')
db = client.cves
collection = db.info

cursor = collection.find()
for i in cursor:
    print(i['pcid'])
    apps = i['apps']
    print(f"app nums:{len(apps)}")
    # for app in apps:
    #     pprint(app)
    pprint(i)