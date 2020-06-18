#!/usr/bin/env python
# encoding: utf-8
"""
@author: Lone
@email: fanml@neusoft.com
@file: mongo_search.py
@time: 2020/6/16 14:01
"""

import pymongo

client = pymongo.MongoClient(host='localhost')
db = client.cves
collection = db.info

cursor = collection.find()
for i in cursor:
    print(i['pcid'])
    apps = i['apps']
    print(len(apps))
    for app in apps:
        print(app)
    # print(i)