#!/usr/bin/env python
# -*- coding: utf-8 -*-
from setuptools import setup, find_packages

with open("README.md", "r") as fh:
    long_description = fh.read()

setup(
    name='drf_ebs_sso',
    version='0.0.1',
    description='Integration of EBS SOO in Django Rest Framework',
    long_description=long_description,
    long_description_content_type="text/markdown",
    author='EBS Integrator',
    author_email='office@ebs-integrator.com',
    url='https://git2.devebs.net/ebs-platform/drf-ebs-sso',
    packages=find_packages(exclude=['tests*']),
    include_package_data=True,
    zip_safe=False,
    classifiers=[
        'Development Status :: 5 - Production/Stable',
        'Environment :: Web Environment',
        'Framework :: Django',
        'Framework :: Django :: 1.11',
        'Framework :: Django :: 2.0',
        'Framework :: Django :: 2.1',
        'Framework :: Django :: 2.2',
        'Intended Audience :: Developers',
        'Operating System :: OS Independent',
        'Programming Language :: Python',
        'Programming Language :: Python :: 3.4',
        'Programming Language :: Python :: 3.5',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7',
        'Topic :: Utilities',
    ],
    python_requires=">=3.4",
    install_requires=[
        'Django>=1.11',
        'djangorestframework',
        'drf_util',
    ],
    license='MIT',
)
