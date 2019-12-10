from setuptools import setup

setup(
    name='yourscript',
    version='0.1',
    py_modules=['yourscript'],
    install_requires=[
        'arrow',
        'click',
        'python-crontab',
        'requests',
    ],
)
