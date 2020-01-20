"""
Setup.py for Smart Cron Helper

Use `pip install --editable .` to install the package.
"""
from setuptools import setup

setup(
    name='SmartCronHelper',
    version='0.1',
    py_modules=['hc'],
    install_requires=[
        'arrow',
        'click',
        'python-crontab',
        'requests',
        'tzlocal',
    ],
)
