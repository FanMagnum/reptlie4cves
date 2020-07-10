#!/usr/bin/env python
# encoding: utf-8
"""
@author: Lone
@email: fanml@neusoft.com
@file: test.py
@time: 2020/6/16 15:49
"""
from pprint import pprint

import psycopg2

conn = psycopg2.connect(dbname='cves', user='postgres', password='123456', host='10.240.200.1', port=5432)
cursor = conn.cursor()

# sql = """SELECT * FROM cveinfo;"""
# cursor.execute(sql)
# rows = cursor.fetchall()
# # print(f"database version: {rows}")
# for row in rows:
#     # print(len(row.apps))
#     print(type(row[1]))
#     pprint(row)

# sql = """SELECT app FROM appinfo WHERE (appinfo.app :: json ->> 'vendor') = %s
#                  AND (appinfo.app :: json ->> 'product') = %s
#                  AND (appinfo.app :: json ->> 'version') = %s;"""
# params = ('google', 'chrome', '83.0.4103.110')
# cursor.execute(sql, params)
# res = cursor.fetchone()[0]
# print(res)
# conn.commit()
# conn.close()