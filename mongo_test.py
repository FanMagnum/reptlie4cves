#!/usr/bin/env python
# encoding: utf-8
"""
@author: Lone
@email: fanml@neusoft.com
@file: mongo_test.py
@time: 2020/6/18 9:57
"""

import pymongo

client = pymongo.MongoClient(host='localhost')
db = client.cves
collection = db.apps
condition = {
    'vendor': 'google',
    'product': 'chrome',
    'version': f'76.0.3809.0'
}
products = collection.find(condition)
print(type(products))
for product in products:
    print(product)