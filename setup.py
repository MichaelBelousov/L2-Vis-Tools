"""
setup script for these tools, mostly installing PyPI
dependencies
"""

# TODO: require inkscape for install

from setuptools import setup, find_packages
from textwrap import dedent

setup(name='L2VisTools',
      version='0.1',
      author='Michael Belousov',
      author_email='michael.belousov98@gmail.com',
      description=dedent('''\
            tools for gathering and visualizing 
            data on layer2 networks'''),
      url='https://github.com/MichaelBelousov/L2VisTools/',
      packages=find_packages(),
      install_requires=[
          'pysecuritycenter',
          'xmltodict',
          'validators',
          'networkx',
          'PyPDF2',
          'svgwrite',
          'svgutils',
          'easysnmp',
          'netaddr',
          'netmiko',
          'oset',
          ]
      )
