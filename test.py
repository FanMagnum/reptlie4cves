#!/usr/bin/env python
# encoding: utf-8
"""
@author: Lone
@email: fanml@neusoft.com
@file: test.py
@time: 2020/6/16 15:49
"""

from fake_useragent import UserAgent

for i in range(100):
    print(UserAgent().random)