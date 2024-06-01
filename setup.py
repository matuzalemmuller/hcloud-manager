import sys
from setuptools import setup


setup(
    name="hcloudmanager",
    version="1.0.0",
    description="test",
    url="https://github.com/matuzalemmuller/hcloud-manager",
    author="Matuzalem (Mat) Muller",
    author_email="matuzalemtech@gmail.com",
    license="MIT",
    packages=["hcloudmanager"],
    include_package_data=True,
    install_requires=["hcloud"],
    entry_points={"console_scripts": ["hcloudmanager = hcloudmanager.__main__:main"]},
    python_requires=">=3.5",  # f-strings
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Intended Audience :: Information Technology",
        "Operating System :: OS Independent",
        "License :: OSI Approved :: GNU General Public License v3 (GPLv3)",
    ],
)
