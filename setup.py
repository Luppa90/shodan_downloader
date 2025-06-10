from setuptools import setup, find_packages

setup(
    name="shodan_downloader",
    version="0.1.0",
    description="A modern Python tool for searching Shodan and exporting filtered results.",
    packages=find_packages(),
    python_requires=">=3.7",
    install_requires=[
        "shodan>=1.28.0",
    ],
    include_package_data=True,
)