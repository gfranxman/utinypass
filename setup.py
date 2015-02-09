import os

from setuptools import setup, find_packages

def read(*paths):
    """Build a file path from *paths* and return the contents."""
    with open(os.path.join(*paths), 'r') as f:
        return f.read()

setup(
    name='utinypass',
    version='0.1.2',
    description='UNOFFICIAL TinyPass utility library.',
    long_description=(read('README.rst') + '\n\n' +
                      read('HISTORY.rst') + '\n\n' +
                      read('AUTHORS.rst') + '\n\n' +
                      read('TODO.rst')),
    url='http://github.com/gfranxman/utinypass/',
    license='MIT',
    author='Glenn Franxman',
    author_email='gfranxman@gmail.com',
    py_modules=['utinypass'],
    include_package_data=True,
    packages=find_packages(exclude=['tests*']),
    install_requires=['pprp',],
    classifiers=[
        'Development Status :: 3 - Alpha',
        'Intended Audience :: Developers',
        'Natural Language :: English',
        'License :: OSI Approved :: MIT License',
        'Operating System :: OS Independent',
        'Programming Language :: Python',
        'Programming Language :: Python :: 2',
        'Programming Language :: Python :: 2.6',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.3',
        'Topic :: Software Development :: Libraries :: Python Modules',
    ],
)
