from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="cryptovault-suite",
    version="1.0.0",
    author="CryptoVault Team",
    description="A comprehensive cryptographic toolkit with secure messaging, file encryption, authentication, and blockchain audit",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/yourusername/cryptovault-suite",
    packages=find_packages(),
    classifiers=[
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Topic :: Security :: Cryptography",
    ],
    python_requires=">=3.9",
    install_requires=[
        "cryptography>=41.0.0",
        "pycryptodome>=3.19.0",
        "PyNaCl>=1.5.0",
        "pyotp>=2.9.0",
        "qrcode>=7.4.2",
    ],
    extras_require={
        "dev": [
            "pytest>=7.4.0",
            "pytest-cov>=4.1.0",
            "black>=23.0.0",
            "flake8>=6.0.0",
            "pylint>=3.0.0",
        ],
    },
    entry_points={
        "console_scripts": [
            "cryptovault=src.main:main",
        ],
    },
)
