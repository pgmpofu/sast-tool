from setuptools import setup, find_packages

setup(
    name="sast-tool",
    version="1.0.0",
    description="Language-agnostic Static Application Security Testing scanner",
    author="Your Name",
    python_requires=">=3.10",
    packages=find_packages(),
    include_package_data=True,
    package_data={"": ["rules/**/*.yaml"]},
    install_requires=[
        "pyyaml>=6.0.1",
        "rich>=13.7.0",
    ],
    entry_points={
        "console_scripts": [
            "sast-tool=main:main",
        ],
    },
)
