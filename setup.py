#!/usr/bin/env python

from setuptools import setup

setup(
    name='firewall',
    version='0.1',
    description='Python firewall using iptables',
    url='https://github.com/',
    author='Zach Bricker',
    author_email='zbricker@my.harrisburgu.edu',
    license='GPLv3+',
    packages=['netfilter'],
    classifiers=[],
    test_suite='tests',
)
