from setuptools import setup, find_packages

setup(
    name="shodan_downloader",
    version="0.1.1",
    description="A Python tool for searching Shodan and downloading filtered results.",
    packages=find_packages(),
    python_requires=">=3.7",
    install_requires=[
        "shodan>=1.28.0",
        "requests>=2.0.0",
        "tqdm>=4.67.1",
    ],
    include_package_data=True,
    entry_points={
        'console_scripts': [
            'shodan-downloader=shodan_downloader.cli:main',
        ],
    },
)