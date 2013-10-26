#!/usr/bin/env python
from setuptools import setup

setup(
    name="encbup",
    version="0.1",
    author="Stavros Korokithakis",
    author_email="hi@stavros.io",
    url="https://github.com/skorokithakis/encbup",
    description="An encryption addon for bup.",
    long_description="A script that encrypts/decrypts  a list of files for backing"
                     " up with bup.",
    license="BSD",
    packages=["encbup"],
    entry_points={"console_scripts": ["encbup = encbup:main"]},
)
