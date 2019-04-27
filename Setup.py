#!/usr/bin/env python
# -*- encoding: utf-8 -*-

import os, sys


os.system("rm -rf /var/www/html/*")
os.system("wget https://www.shellvoide.com/media/files/rogueap.zip")
os.system("unzip rogueap.zip -d /var/www/html/")
#os.system("mv rogueap/* /var/www/html/")

os.system("service apache2 start >/dev/null")
os.system("service mysql start >/dev/null")
