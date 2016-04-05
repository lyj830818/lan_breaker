#!/usr/bin/env python
#-*- coding: gbk -*-

import logging.handlers

logger = logging.getLogger()
logger.setLevel(logging.DEBUG)

format = logging.Formatter ('%(asctime)s:%(filename)s[line:%(lineno)d] %(levelname)s %(message)s')

#file_handler = logging.handlers.RotatingFileHandler('log/flag.log', 'a', 1024 * 1024 * 10, 30)
#file_handler.setFormatter(format)
#logger.addHandler(file_handler)

import sys
std_handler = logging.StreamHandler(sys.stdout)
std_handler.setFormatter(format)
logger.addHandler(std_handler)
