from setuptools import setup, find_packages

setup(
    name="leakhawk",
    version="0.1.0",
    description="Runtime Secrets Detection for AWS",
    author="LeakHawk Team",
    author_email="info@leakhawk.com",
    packages=find_packages(),
    install_requires=[
        "boto3>=1.26.0",
    ],
    entry_points={
        "console_scripts": [
            "leakhawk=leakhawk:main",
        ],
    },
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
    ],
    python_requires=">=3.8",
)
