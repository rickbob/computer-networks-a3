#!/usr/bin/env python
'''Setuptools params'''

from setuptools import setup, find_packages

setup(
    name='cs356',
    version='1.0.0',
    description='Network controller for CS356 Assignments',
    author='',
    author_email='huangty@stanford.edu agember@cs.wisc.edu adney11@cs.utexas.edu',
    packages=find_packages(exclude='test'),
    long_description="""\
      Updated wisc references to adapt to UT CS356 Course
      """,
      classifiers=[
          "License :: OSI Approved :: GNU General Public License (GPL)",
          "Programming Language :: Python",
          "Development Status :: 1 - Planning",
          "Intended Audience :: Developers",
          "Topic :: Internet",
      ],
      keywords='stanford cs144 uw-madison cs640 ut-austin cs356',
      license='GPL',
      install_requires=[
        'setuptools',
        'twisted',
        'ltprotocol', # David Underhill's nice Length-Type protocol handler
      ])

