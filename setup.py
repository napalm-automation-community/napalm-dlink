"""setup.py file."""

from setuptools import setup, find_packages

__author__ = 'Chobanov Nikolay <hromus@gmail.com>'

with open("README.md", "r") as fh:
    long_description = fh.read()


def parse_reqs(file_path):
    """Parse requirements from file."""
    with open(file_path, 'rt') as fobj:
        lines = map(str.strip, fobj)
        lines = filter(None, lines)
        lines = filter(lambda x: not x.startswith("#"), lines)
        return tuple(lines)


setup(
    name="napalm-dlink",
    version="0.1.0",
    packages=find_packages(),
    author="Nikolay Chobanov",
    author_email="hromus@gmail.com",
    description="NAPALM driver for Dlink",
    long_description_content_type="text/markdown",
    long_description=long_description,
    classifiers=[
        'Topic :: Utilities',
        'Programming Language :: Python',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.7',
        'Operating System :: POSIX :: Linux',
    ],
    url="https://github.com/napalm-automation/napalm-dlink",
    include_package_data=True,
    install_requires=parse_reqs('requirements.txt'),
)
