#!/usr/bin/env python

"""The setup script."""

from setuptools import setup, find_packages

with open('README.md') as readme_file:
    readme = readme_file.read()

with open('HISTORY.md') as history_file:
    history = history_file.read()

requirements = [
    'arrow',
    'click>=7.0',
    'python-crontab',
    'requests',
    'configparser',
    'tzlocal',
    'ttictoc',
    ]

setup_requirements = []

test_requirements = []

setup(
    author="Bram Daams",
    author_email='b.daams@science.ru.nl',
    python_requires='>=3.5',
    classifiers=[
        'Development Status :: 2 - Pre-Alpha',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: GNU General Public License v3 (GPLv3)',
        'Natural Language :: English',
        "Topic :: System :: Monitoring",
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.5',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7',
        'Programming Language :: Python :: 3.8',
    ],
    description="A cron shell wrapper for registering and "
                "updating cron jobs automatically in healthchecks",
    entry_points={
        'console_scripts': [
            'sch=sch.cli:main',
        ],
    },
    install_requires=requirements,
    license="GNU General Public License v3",
    long_description=readme + '\n\n' + history,
    long_description_content_type="text/markdown",
    include_package_data=True,
    keywords='sch',
    name='sch',
    packages=find_packages(include=['sch', 'sch.*']),
    setup_requires=setup_requirements,
    test_suite='tests',
    tests_require=test_requirements,
    url='https://gitlab.science.ru.nl/bram/sch',
    version='0.2.1',
    zip_safe=False,
)
