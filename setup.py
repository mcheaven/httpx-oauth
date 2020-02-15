#!/usr/bin/env python
# setup.py generated by flit for tools that don't yet use PEP 517

from setuptools import setup

packages = \
['httpx_oauth', 'httpx_oauth.clients', 'httpx_oauth.integrations']

package_data = \
{'': ['*']}

install_requires = \
['httpx >=0.11,<0.12', 'typing-extensions', 'google-auth']

setup(name='httpx-oauth',
      version='0.2.1',
      description='Async OAuth client using HTTPX.',
      author='François Voron',
      author_email='fvoron@gmail.com',
      url='https://github.com/frankie567/httpx-oauth',
      packages=packages,
      package_data=package_data,
      install_requires=install_requires,
      python_requires='>=3.7',
     )
