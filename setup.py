"""
Setup.py for Smart Cron Helper

Use `pip install .` to install the package.
"""
from setuptools import setup

setup(
    name='SmartCronHelper',
    version='0.1',
    py_modules=['hc', 'sch'],
    install_requires=[
        'arrow',
        'click',
        'python-crontab',
        'requests',
        'configparser',
        'tzlocal',
    ],
    entry_points='''
        [console_scripts]
        sch=sch:run
        ''',
)
