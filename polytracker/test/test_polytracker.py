import os
import sys

if sys.version_info < (3, 7):
    sys.exit('This script must be run with at least Python 3.7')

import contextlib
import os
# import pytest
import subprocess

from os.path import dirname, join as join, realpath
from pathlib import Path
from shutil import which
from subprocess import check_call, run

from typing import Generator, Optional


################################################################################
# Utilities
################################################################################
def _find_program(name: str) -> str:
    res = which(name)
    if res is None:
        raise ValueError(f"unable to find `{name}` -- perhaps it's not in your PATH?")
    return res

# Cribbed from here: https://stackoverflow.com/a/24176022/201217
#
# Also yields the previous directory after changing, so you can use like
#
#     with chdir(new_dir) as prev_dir:
#         ...
@contextlib.contextmanager
def chdir(d) -> Generator[str, None, None]:
    prev_d = os.getcwd()
    os.chdir(d)
    try:
        yield prev_d
    finally:
        os.chdir(prev_d)


################################################################################
# Globals
################################################################################
PC: str   = _find_program('polyclang')
PCPP: str = _find_program('polyclang++')
TESTS_DIR = realpath(dirname(__file__))


################################################################################
# Test cases here!
################################################################################
def test_test1(tmpdir) -> None:
    with chdir(tmpdir):
        check_call([PC, '-Wall', '-O2', join(TESTS_DIR, 'test1.c'), '-o', 'test1'])
        check_call(['./test1'])

def test_test2(tmpdir) -> None:
    with chdir(tmpdir):
        check_call([PCPP, '-Wall', '-O2', join(TESTS_DIR, 'test2.cpp'), '-o', 'test2'])
        check_call(['./test2'])

def test_build_mupdf(tmpdir) -> None:
    os.makedirs('downloads', exist_ok=True)
    mupdf_dirname = 'mupdf-1.16.1-source'
    mupdf_tarball = join('downloads', f'{mupdf_dirname}.tar.gz')
    check_call(['wget', '-qc', f'https://mupdf.com/downloads/archive/{mupdf_dirname}.tar.gz', '-O', mupdf_tarball])
    run(['sha1sum', '-c'], input=f'ccbef63c3d43d6a866b7978db5674dc4b1719f0f  {mupdf_tarball}'.encode(), check=True)
    pc_env = os.environ.copy()
    pc_env['CC'] = PC
    pc_env['CXX'] = PCPP
    with chdir(tmpdir) as prev_dir:
        check_call(['tar', '-xzf', join(prev_dir, mupdf_tarball)])
        check_call(['make', '-C', mupdf_dirname, 'HAVE_GLUT=no', 'HAVE_X11=no', 'build=debug', '-j4'], env=pc_env)
