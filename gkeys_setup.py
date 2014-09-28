#!/usr/bin/env python

import os
import sys

from distutils.core import setup
from gkeys import __version__, __license__

# this affects the names of all the directories we do stuff with
sys.path.insert(0, './')

#__version__ = os.getenv('VERSION', default='9999')

# Load EPREFIX from Portage, fall back to the empty string if it fails
try:
    from portage.const import EPREFIX
except ImportError:
    EPREFIX=''


setup(
    name='gkeys',
    version=__version__,
    description="Gentoo gpg key management and Python interface to gpg",
    author='',
    author_email='',
    maintainer='Gentoo-Keys Team',
    maintainer_email='gkeys@gentoo.org',
    url="https://wiki.gentoo.org/wiki/Project:Gentoo-keys",
    download_url='http://distfiles.gentoo.org/distfiles/gkeys-%s.tar.gz'\
        % __version__,
    packages=['gkeys'],
    scripts=['bin/gkeys'],
    data_files=(
        (os.path.join(os.sep, EPREFIX.lstrip(os.sep), 'etc'), ['etc/gkeys.conf']),
        (os.path.join(os.sep, EPREFIX.lstrip(os.sep), 'etc'), ['etc/gkeys.conf.sample']),
        ),
    license=__license__,
    long_description=open('README.md').read(),
    keywords='gpg',
    classifiers=[
        'Development Status :: 3 - Alpha',
        'Intended Audience :: Developers, Users',
        'License :: OSI Approved :: GPLv2 License',
        'Programming Language :: Python :: 2.7, 3.3, 3.4, +',
        'Operating System :: OS Independent',
        'Topic :: Security :: Cryptography',
    ],
)
