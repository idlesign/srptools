import os
import io
import re
import sys
from setuptools import setup, find_packages


PATH_BASE = os.path.dirname(__file__)
PYTEST_RUNNER = ['pytest-runner'] if 'test' in sys.argv else []


def read(fpath):
    return io.open(fpath).read()


def get_version():
    """Reads version number.

    This workaround is required since __init__ is an entry point exposing
    stuff from other modules, which may use dependencies unavailable
    in current environment, which in turn will prevent this application
    from install.

    """
    contents = read(os.path.join(PATH_BASE, 'srptools', '__init__.py'))
    version = re.search('VERSION = \(([^)]+)\)', contents)
    version = version.group(1).replace(', ', '.').strip()
    return version


setup(
    name='srptools',
    version=get_version(),
    url='https://github.com/idlesign/srptools',

    description='Tools to implement Secure Remote Password (SRP) authentication',
    long_description=read(os.path.join(PATH_BASE, 'README.rst')),
    license='BSD 3-Clause License',

    author='Igor `idle sign` Starikov',
    author_email='idlesign@yandex.ru',

    packages=find_packages(),
    include_package_data=True,
    zip_safe=False,

    install_requires=['six'],
    setup_requires=[] + PYTEST_RUNNER,
    extras_require={'cli':  ['click>=2.0']},
    tests_require=['pytest'],

    entry_points={'console_scripts': ['srptools = srptools.cli:main']},

    test_suite='tests',

    classifiers=[
        # As in https://pypi.python.org/pypi?:action=list_classifiers
        'Development Status :: 4 - Beta',
        'Operating System :: OS Independent',
        'Programming Language :: Python',
        'Programming Language :: Python :: 2',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.3',
        'Programming Language :: Python :: 3.4',
        'Programming Language :: Python :: 3.5',
        'Programming Language :: Python :: 3.6',
        'License :: OSI Approved :: BSD License'
    ],
)
