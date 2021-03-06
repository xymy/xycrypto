from pathlib import Path

from setuptools import find_packages, setup

from xycrypto import __version__, __author__

readme = Path(__file__).with_name('README.md').read_text()

classifiers = [
    'License :: OSI Approved',
    'License :: OSI Approved :: MIT License',
    'Operating System :: OS Independent',
    'Programming Language :: Python',
    'Programming Language :: Python :: 3',
    'Programming Language :: Python :: 3.6',
    'Programming Language :: Python :: 3.7',
    'Programming Language :: Python :: 3.8',
    'Topic :: Security',
    'Topic :: Security :: Cryptography'
]

setup(
    name='xycrypto',
    version=__version__,
    license='MIT',

    description='A friendly cryptographic primitives library.',
    long_description=readme,
    long_description_content_type='text/markdown',

    author=__author__,
    author_email='thyfan@163.com',
    url='https://github.com/xymy/xycrypto',

    classifiers=classifiers,

    package_dir={'': 'src'},
    packages=find_packages('src'),
    include_package_data=True,

    install_requires=[
        'cryptography>=2.8',
    ],
    python_requires='>=3.6'
)
