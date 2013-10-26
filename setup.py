#!/usr/bin/env python
from setuptools import setup
from encbup import VERSION

setup(
    name="encbup",
    version=VERSION,
    author="Stavros Korokithakis",
    author_email="hi@stavros.io",
    test_suite='nose.collector',
    url="https://github.com/skorokithakis/encbup",
    description="An encryption addon for bup.",
    long_description="A script that encrypts/decrypts  a list of files for backing"
                     " up with bup.",
    license="BSD",
    install_requires=["docopt>=0.6", "pycrypto>=2.6"],
    packages=["encbup"],
    entry_points={"console_scripts": ["encbup = encbup:main"]},
)
