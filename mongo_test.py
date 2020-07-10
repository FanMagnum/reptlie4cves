#!/usr/bin/env python
# encoding: utf-8
"""
@author: Lone
@email: fanml@neusoft.com
@file: mongo_test.py
@time: 2020/6/18 9:57
"""

import pymongo

client = pymongo.MongoClient(host='10.240.200.1')
db = client.cves
collection = db.apps
condition = {
    'vendor': 'microsoft',
    'product': 'office',
    'version': '2017'
}
products = collection.find_one(condition)
print(type(products))
print(products)
print(len(products['cves']))
# collection.delete_one(products)
# for product in products:
# #     print(product)