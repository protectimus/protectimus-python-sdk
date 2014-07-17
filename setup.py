#!/usr/bin/python
# -*- coding: utf-8 -*-

try: import setuptools
except ImportError:
    import distribute_setup
    distribute_setup.use_setuptools()
from setuptools import setup

setup(
    name = 'protectimusapi',
    version = '0.0.1',
    packages = ['protectimussdk'],
    setup_requires = [
        'rfc3987 >= 1.3.2',
        'lxml >= 2.3.4',
    ]
)