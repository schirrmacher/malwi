from setuptools import setup, find_packages

setup(
    name="malwi",
    version="0.0.4",
    author="Marvin Schirrmacher",
    author_email="m@schirrmacher.io",
    description="malwi - AI Python Malware Scanner",
    long_description=open("README.md").read(),
    long_description_content_type="text/markdown",
    url="https://github.com/schirrmacher/malwi",
    packages=find_packages(where="src"),
    package_dir={"": "src"},
    include_package_data=True,
    package_data={
        "research.syntax_mapping": [
            "compression_mapping.json",
            "function_mapping.json",
            "import_mapping.json",
            "node_mapping.json",
            "node_targets.json",
            "sensitive_files.json",
            "special_tokens.json",
            "target_files.json",
        ]
    },
    install_requires=[
        # Add any dependencies here
    ],
    python_requires=">=3.7",
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
)
