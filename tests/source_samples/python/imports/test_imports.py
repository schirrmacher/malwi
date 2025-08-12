# Python Import Patterns Test Suite
# Tests various import patterns commonly seen in both legitimate and malicious code

# Standard library imports (common in legitimate code)
import os
import subprocess
import socket
import urllib.request
import base64
import pickle
import marshal
import types
import importlib
import tempfile
import shutil
import pathlib

# From imports with various patterns
from os import environ, path, listdir
from sys import argv, exit, modules, path as sys_path
from subprocess import run, Popen, PIPE, call
from socket import socket, AF_INET, SOCK_STREAM
from urllib.parse import urlparse, urljoin
from urllib.request import urlopen, Request
from base64 import b64encode, b64decode, decodebytes
from pickle import loads, dumps, load, dump
from marshal import loads as marshal_loads, dumps as marshal_dumps
from types import CodeType, ModuleType
from importlib import import_module, util
from tempfile import mkstemp, mkdtemp, NamedTemporaryFile
from shutil import rmtree, copytree, move
from pathlib import Path, PurePath

# Aliased imports (can be used to obfuscate intent)
import os as operating_system
import subprocess as subproc
import socket as sock
import urllib.request as web_request
import base64 as b64
import pickle as pkl
import marshal as marsh
import types as tp
import importlib as imp_lib

# Multiple from-imports on one line
from os.path import join, exists, isfile, isdir, basename, dirname

# Nested module imports
from os.path import join as path_join, exists as path_exists
from urllib.request import urlopen as open_url, Request as web_request_obj
from base64 import b64encode as encode_b64, b64decode as decode_b64

# Conditional imports (pattern often seen in malware for evasion)
try:
    import ctypes
    from ctypes import windll, wintypes

    ctypes_available = True
except ImportError:
    ctypes_available = False

try:
    import win32api
    from win32api import GetSystemMetrics

    win32_available = True
except ImportError:
    win32_available = False

try:
    import requests
    from requests import get, post, Session

    requests_available = True
except ImportError:
    requests_available = False

# Potentially suspicious imports (common in malware)
try:
    import keyring
    from keyring import get_password, set_password
except ImportError:
    pass

try:
    import sqlite3
    from sqlite3 import connect, Row
except ImportError:
    pass

try:
    import winreg
    from winreg import OpenKey, QueryValueEx, HKEY_LOCAL_MACHINE
except ImportError:
    pass


# Dynamic imports (often used in malware for obfuscation)
def dynamic_import_test():
    # These patterns are commonly used to evade static analysis
    module_name = "os"
    imported_os = __import__(module_name)

    getattr_call = getattr(imported_os, "system")
    exec_func = getattr(__builtins__, "exec")
    eval_func = getattr(__builtins__, "eval")


print("Import patterns test completed")
