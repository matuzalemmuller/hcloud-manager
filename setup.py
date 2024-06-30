import sys
from setuptools import setup


setup(
    name="hcloudmanager",
    version="1.1.3",
    description="",
    url="https://github.com/matuzalemmuller/hcloud-manager",
    author="Matuzalem (Mat) Muller",
    author_email="matuzalemtech@gmail.com",
    license="MIT",
    packages=["hcloudmanager"],
    include_package_data=True,
    install_requires=["hcloud"],
    entry_points={"console_scripts": ["hcloudmanager = hcloudmanager.__main__:main"]},
    python_requires=">=3.10",  # 3.10 just because I haven't tested an older version ¯\_(ツ)_/¯
    classifiers=[
        "Intended Audience :: Information Technology",
    ],
)
