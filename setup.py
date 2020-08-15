from os import path
from setuptools import find_packages, setup


current_dir = path.abspath(path.dirname(__file__))
with open(path.join(current_dir, 'README.md'), encoding='utf-8') as f:
    long_description = f.read()

setup(
    name='google-yubikey',
    author='Denis Loginov',
    description='Generate Google Service Account tokens with your YubiKey',
    long_description=long_description,
    long_description_content_type='text/markdown',
    license='BSD 3-clause "New" or "Revised" License',
    url='https://github.com/dinvlad/google-yubikey',
    classifiers=[
        'Development Status :: 3 - Alpha',
        'License :: OSI Approved :: BSD License',
        'Operating System :: OS Independent',
        'Programming Language :: Python :: 3 :: Only',
        'Topic :: Security',
        'Topic :: Security :: Cryptography',
        'Topic :: Utilities',
    ],
    python_requires='>=3.7.0',
    packages=find_packages(
        exclude=[
            'tests',
        ],
    ),
    setup_requires=[
        'setuptools_scm',
    ],
    use_scm_version={
        'root': '.',
        'relative_to': __file__,
    },
    install_requires=[
        'google-api-python-client >= 1.10.0',
        'requests >= 2.24.0',
        'yubikey-manager >= 3.1.1',
    ],
    entry_points={
        'console_scripts': [
            'google-yubikey = google_yubikey.__init__:main',
        ],
    },
)
